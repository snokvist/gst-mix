// UDP source selector + low-latency H.265 viewer via GStreamer appsrc (IPv4 only).
// Adds "stats" on stdin:
//   • Per-source UDP counters + RTP analysis (unique/expected/lost/dup/reorder, RFC3550 jitter)
//   • Decoder info: width×height/format/framerate + instant/avg FPS (probe on vaapih265dec:src)
//   • QoS bus watcher: per-element aggregates (processed/dropped, jitter last/avg/min/max, proportion, quality)
//
// Pipeline (low-latency oriented):
//   appsrc (is-live, format=bytes, RTP caps) ! capsfilter ! queue(leaky) ! rtpjitterbuffer(latency=8)
//     ! rtph265depay ! vaapih265dec ! xvimagesink
//
// Build (Ubuntu/Debian):
//   sudo apt install build-essential pkg-config libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev gstreamer1.0-vaapi
//   gcc -std=c11 -O2 -Wall main.c -o udp-h265-viewer $(pkg-config --cflags --libs \
//       gstreamer-1.0 gstreamer-app-1.0 gstreamer-video-1.0 gobject-2.0 glib-2.0)

#define _GNU_SOURCE
#include <gst/gst.h>
#include <gst/app/gstappsrc.h>
#include <glib.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>

#ifndef RELAY_MAX_SOURCES
#define RELAY_MAX_SOURCES 256
#endif
#ifndef RELAY_BUF_SIZE
#define RELAY_BUF_SIZE 65536
#endif
#ifndef RTP_WIN_SIZE   // sliding uniqueness window for seqs (power of two recommended)
#define RTP_WIN_SIZE 4096
#endif
#define RTP_SLOT_EMPTY 0xffffffffu

typedef struct {
    struct sockaddr_in addr;  // IPv4 only
    socklen_t addrlen;
    bool in_use;

    // UDP counters
    uint64_t pkts;        // received
    uint64_t bytes;       // received
    uint64_t fwd_pkts;    // forwarded to appsrc (GST_FLOW_OK)
    uint64_t fwd_bytes;   // forwarded bytes
    gint64   last_seen_us;

    // Instantaneous bitrate between stats calls
    uint64_t prev_bytes;
    gint64   prev_t_us;

    // --- RTP analysis (relay-side) ---
    bool     rtp_init;
    uint32_t cycles;            // wrap cycles << 16 for 16-bit RTP seq
    uint16_t last_seq;          // last 16-bit seq observed
    uint32_t first_ext_seq;     // first extended seq observed
    uint32_t max_ext_seq;       // highest extended seq observed

    uint64_t rtp_unique;        // unique RTP packets (dedup within window)
    uint64_t rtp_dups;          // duplicates within the window
    uint64_t rtp_reordered;     // arrived with ext_seq < max_ext_seq (and not duplicate)

    // Rolling table for uniqueness / dedup (ext_seq -> slot)
    uint32_t seq_slot[RTP_WIN_SIZE];

    // RFC3550 interarrival jitter (in RTP ts units, smoothed)
    bool     jitter_init;
    uint32_t prev_transit;
    double   jitter;
} Source;

typedef struct {
    int listen_port;              // where cameras send to
    GThread *thread;
    volatile sig_atomic_t running;
    volatile sig_atomic_t push_enabled; // gated by appsrc callbacks

    Source sources[RELAY_MAX_SOURCES];
    int sources_count;
    int selected_idx;

    GstAppSrc *appsrc; // thread-safe appsrc handle
} RelayCtx;

typedef struct {
    int payload;
    int clockrate;
    gboolean sync;
    GMainLoop *loop;

    GstElement *pipeline;
    GstElement *appsrc_e;
    GstElement *queue0;
    GstElement *jbuf;
    GstElement *depay;
    GstElement *decoder;
    GstElement *sink;
} GstCtx;

typedef struct {
    GMutex  lock;
    guint64 frames_total;
    gint64  first_us;
    guint64 prev_frames;
    gint64  prev_us;
} DecStats;

// QoS per-element aggregates
typedef struct {
    guint64 processed;          // from QoS message (format-dependent)
    guint64 dropped;
    guint64 events;             // number of QoS messages seen

    gint64  last_jitter_ns;     // QoS jitter from message (ns, signed)
    gint64  min_jitter_ns;
    gint64  max_jitter_ns;
    long double sum_abs_jitter_ns;

    gdouble last_proportion;    // <1: speed up, >1: slow down (sink perspective)
    gint    last_quality;       // 0..100 (typical)
    gboolean live;
} QoSStats;

typedef struct {
    GHashTable *table; // key: char* element path, value: QoSStats*
    GMutex lock;
} QoSDB;

static RelayCtx g_relay = {0};
static GstCtx   g_gst   = {0};
static DecStats g_dec   = {0};
static QoSDB    g_qos   = {0};

// ---------------- utils ----------------
static void addr_to_str(const struct sockaddr_in *sa, char *out, size_t outlen) {
    char ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
    int port = ntohs(sa->sin_port);
    snprintf(out, outlen, "%s:%d", ip, port);
}

static void relay_print_sources(RelayCtx *rc) {
    if (rc->sources_count == 0) {
        g_print("No sources discovered yet.\n");
        return;
    }
    g_print("Known sources:\n");
    for (int i = 0; i < rc->sources_count; i++) {
        if (!rc->sources[i].in_use) continue;
        char s[64]; addr_to_str(&rc->sources[i].addr, s, sizeof(s));
        g_print("  [%d]%s %s\n", i, (i == rc->selected_idx ? " *" : "  "), s);
    }
}

static bool relay_add_or_find(RelayCtx *rc, const struct sockaddr_in *from, socklen_t fromlen, int *out_idx) {
    for (int i = 0; i < rc->sources_count; i++) {
        if (!rc->sources[i].in_use) continue;
        if (rc->sources[i].addrlen == fromlen && memcmp(&rc->sources[i].addr, from, fromlen) == 0) {
            if (out_idx) *out_idx = i;
            return false;
        }
    }
    if (rc->sources_count >= RELAY_MAX_SOURCES) return false;
    Source *ns = &rc->sources[rc->sources_count];
    ns->addr = *from;
    ns->addrlen = fromlen;
    ns->in_use = true;

    ns->pkts = ns->bytes = ns->fwd_pkts = ns->fwd_bytes = 0;
    ns->last_seen_us = 0;
    ns->prev_bytes = 0;
    ns->prev_t_us = 0;

    ns->rtp_init = false;
    ns->cycles = 0;
    ns->last_seq = 0;
    ns->first_ext_seq = 0;
    ns->max_ext_seq = 0;
    ns->rtp_unique = 0;
    ns->rtp_dups = 0;
    ns->rtp_reordered = 0;
    for (int i = 0; i < RTP_WIN_SIZE; ++i) ns->seq_slot[i] = RTP_SLOT_EMPTY;

    ns->jitter_init = false;
    ns->prev_transit = 0;
    ns->jitter = 0.0;

    if (out_idx) *out_idx = rc->sources_count;
    rc->sources_count++;
    return true;
}

static void print_human_bitrate(double bps, char *out, size_t outlen) {
    if (bps < 1000.0)        snprintf(out, outlen, "%.0f bps", bps);
    else if (bps < 1e6)      snprintf(out, outlen, "%.2f kbps", bps/1e3);
    else if (bps < 1e9)      snprintf(out, outlen, "%.2f Mbps", bps/1e6);
    else                     snprintf(out, outlen, "%.2f Gbps", bps/1e9);
}

// --- helpers for RTP math ---
static inline uint32_t rtp_ext_seq(Source *s, uint16_t seq16) {
    if (s->rtp_init) {
        if (seq16 < s->last_seq && (uint16_t)(s->last_seq - seq16) > 30000) {
            s->cycles += 1u << 16; // wrap
        }
    }
    s->last_seq = seq16;
    return s->cycles + seq16;
}

static inline uint32_t rtp_now_ts(int clockrate) {
    gint64 us = g_get_monotonic_time();
    long double ts = ((long double)us * (long double)clockrate) / 1000000.0L;
    if (ts < 0) ts = 0;
    uint64_t v = (uint64_t)ts;
    return (uint32_t)v; // wrap naturally
}

// -------- RTP v2 parser + stats update --------
static inline void rtp_update_stats(Source *s, const unsigned char *p, size_t len, int clockrate) {
    if (len < 12) return;
    if ((p[0] & 0xC0) != 0x80) return; // Version 2 check

    uint16_t seq = (uint16_t)((p[2] << 8) | p[3]);
    uint32_t ts  = (uint32_t)((p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7]);

    uint32_t ext = rtp_ext_seq(s, seq);
    if (!s->rtp_init) {
        s->rtp_init = true;
        s->first_ext_seq = ext;
        s->max_ext_seq   = ext;
    }

    // Dedupe / reorder via rolling table
    uint32_t idx = ext % RTP_WIN_SIZE;
    if (s->seq_slot[idx] == ext) {
        s->rtp_dups++;
    } else {
        if (ext < s->max_ext_seq) s->rtp_reordered++;
        s->seq_slot[idx] = ext;
        s->rtp_unique++;
        if (ext > s->max_ext_seq) s->max_ext_seq = ext;
    }

    // RFC3550 interarrival jitter
    uint32_t arrival_ts = rtp_now_ts(clockrate);
    uint32_t transit = arrival_ts - ts; // wrap arithmetic
    if (!s->jitter_init) {
        s->jitter_init = true;
        s->prev_transit = transit;
    } else {
        int32_t d = (int32_t)(transit - s->prev_transit);
        if (d < 0) d = -d;
        s->jitter += ((double)d - s->jitter) / 16.0; // EWMA
        s->prev_transit = transit;
    }
}

// ---------------- QoS DB ----------------
static void qos_stats_free(gpointer data) {
    QoSStats *qs = (QoSStats*)data;
    g_free(qs);
}
static void qos_db_init(QoSDB *db) {
    g_mutex_init(&db->lock);
    db->table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, qos_stats_free);
}
static void qos_db_clear(QoSDB *db) {
    if (!db->table) return;
    g_hash_table_remove_all(db->table);
}

static void qos_update_from_msg(GstMessage *msg) {
    // Identify the element that emitted the QoS
    GstObject *src = GST_MESSAGE_SRC(msg);
    if (!src) return;
    gchar *path = gst_object_get_path_string(src); // e.g. "pipeline0/dec"
    if (!path) return;

    gboolean live = FALSE;
    guint64 running_time=0, stream_time=0, timestamp=0, duration=0;
    gst_message_parse_qos(msg, &live, &running_time, &stream_time, &timestamp, &duration);

    GstFormat fmt = GST_FORMAT_UNDEFINED;
    guint64 processed=0, dropped=0;
    gst_message_parse_qos_stats(msg, &fmt, &processed, &dropped);

    gint64 jitter_ns = 0; gdouble proportion = 0.0; gint quality = 0;
    gst_message_parse_qos_values(msg, &jitter_ns, &proportion, &quality);

    g_mutex_lock(&g_qos.lock);
    QoSStats *qs = (QoSStats*)g_hash_table_lookup(g_qos.table, path);
    if (!qs) {
        qs = g_new0(QoSStats, 1);
        qs->min_jitter_ns = G_MAXINT64;
        qs->max_jitter_ns = G_MININT64;
        g_hash_table_insert(g_qos.table, path, qs); // takes ownership of 'path'
    } else {
        g_free(path); // key existed; free our temp
    }

    qs->events++;
    qs->processed = processed; // latest snapshot
    qs->dropped   = dropped;
    qs->last_jitter_ns  = jitter_ns;
    if (jitter_ns < qs->min_jitter_ns) qs->min_jitter_ns = jitter_ns;
    if (jitter_ns > qs->max_jitter_ns) qs->max_jitter_ns = jitter_ns;
    qs->sum_abs_jitter_ns += (long double)( (jitter_ns < 0) ? -jitter_ns : jitter_ns );
    qs->last_proportion = proportion;
    qs->last_quality = quality;
    qs->live = live;

    g_mutex_unlock(&g_qos.lock);
}

static void qos_print(void) {
    g_mutex_lock(&g_qos.lock);
    if (!g_qos.table || g_hash_table_size(g_qos.table) == 0) {
        g_print("QoS: (no messages yet)\n");
        g_mutex_unlock(&g_qos.lock);
        return;
    }
    GHashTableIter it; gpointer k, v;
    g_hash_table_iter_init(&it, g_qos.table);
    g_print("---- QoS (per element) ----\n");
    while (g_hash_table_iter_next(&it, &k, &v)) {
        const char *path = (const char*)k;
        QoSStats *qs = (QoSStats*)v;
        double last_ms = qs->last_jitter_ns / 1e6;
        double avg_ms  = (qs->events ? (double)(qs->sum_abs_jitter_ns / (long double)qs->events) / 1e6 : 0.0);
        double min_ms  = (qs->min_jitter_ns==G_MAXINT64?0.0: (qs->min_jitter_ns/1e6));
        double max_ms  = (qs->max_jitter_ns==G_MININT64?0.0: (qs->max_jitter_ns/1e6));
        g_print("%s  proc=%" PRIu64 " drop=%" PRIu64
        "  jitter(ms): last=%.2f avg|min|max=%.2f|%.2f|%.2f"
        "  prop=%.3f qual=%d live=%d\n",
        path, qs->processed, qs->dropped,
        last_ms, avg_ms, min_ms, max_ms,
        qs->last_proportion, qs->last_quality, qs->live ? 1 : 0);
    }
    g_mutex_unlock(&g_qos.lock);
}

// ---------------- stats print ----------------
static void stats_print(RelayCtx *rc, GstCtx *gc) {
    gint64 now_us = g_get_monotonic_time();

    // Per-source
    if (rc->sources_count == 0) {
        g_print("No sources discovered yet.\n");
    } else {
        g_print("---- Sources ----\n");
        for (int i = 0; i < rc->sources_count; i++) {
            Source *s = &rc->sources[i];
            if (!s->in_use) continue;
            char addr[64]; addr_to_str(&s->addr, addr, sizeof(addr));

            // Instant bitrate since last stats call for THIS source
            double ibps = 0.0;
            if (s->prev_t_us != 0 && now_us > s->prev_t_us && s->bytes >= s->prev_bytes) {
                uint64_t dbytes = s->bytes - s->prev_bytes;
                double dt = (now_us - s->prev_t_us) / 1e6;
                if (dt > 0.0) ibps = (double)dbytes * 8.0 / dt;
            }
            s->prev_bytes = s->bytes;
            s->prev_t_us  = now_us;

            char ibuf[64]; print_human_bitrate(ibps, ibuf, sizeof(ibuf));
            double age_s = (s->last_seen_us > 0) ? (now_us - s->last_seen_us)/1e6 : -1.0;

            // Expected vs unique (may decrease "lost" as late packets arrive)
            uint64_t expected = 0, lost = 0;
            if (s->rtp_init) {
                expected = (uint64_t)(s->max_ext_seq - s->first_ext_seq + 1);
                if (expected > s->rtp_unique) lost = expected - s->rtp_unique;
            }

            double rfc_jitter_ms = (s->jitter * 1000.0) / (double)gc->clockrate;

            g_print("[%d]%s %s  rx_pkts=%" PRIu64 " rx_bytes=%" PRIu64
            "  fwd_pkts=%" PRIu64 " fwd_bytes=%" PRIu64
            "  rate=%s  last_seen=%.1fs"
            "  | rtp_unique=%" PRIu64 " exp=%" PRIu64 " lost=%" PRIu64
            " dup=%" PRIu64 " reord=%" PRIu64 " rfc3550_jitter=%.2fms\n",
            i, (i==rc->selected_idx?"*":""), addr,
                    s->pkts, s->bytes,
                    s->fwd_pkts, s->fwd_bytes,
                    ibuf, (age_s>=0?age_s:0.0),
                    s->rtp_unique, expected, lost, s->rtp_dups, s->rtp_reordered, rfc_jitter_ms);
        }
    }

    // Pipeline stats
    g_print("---- Pipeline ----\n");
    if (gc->queue0) {
        gint q_lvl_buf=0; guint q_lvl_bytes=0; guint64 q_lvl_time=0;
        g_object_get(gc->queue0,
                     "current-level-buffers", &q_lvl_buf,
                     "current-level-bytes",   &q_lvl_bytes,
                     "current-level-time",    &q_lvl_time,
                     NULL);
        g_print("queue0: level buffers=%d bytes=%u time=%.1fms\n",
                q_lvl_buf, q_lvl_bytes, q_lvl_time/1e6);
    }

    // Decoder FPS + caps
    double inst_fps = 0.0, avg_fps = 0.0;
    guint64 frames_total;
    gint64 first_us, prev_us;
    guint64 prev_frames;
    g_mutex_lock(&g_dec.lock);
    frames_total = g_dec.frames_total;
    first_us     = g_dec.first_us;
    prev_us      = g_dec.prev_us;
    prev_frames  = g_dec.prev_frames;
    g_dec.prev_us = now_us;
    g_dec.prev_frames = frames_total;
    g_mutex_unlock(&g_dec.lock);

    if (prev_us != 0 && now_us > prev_us && frames_total >= prev_frames) {
        double dt = (now_us - prev_us) / 1e6;
        if (dt > 0.0) inst_fps = (double)(frames_total - prev_frames) / dt;
    }
    if (first_us != 0 && now_us > first_us) {
        double dt = (now_us - first_us) / 1e6;
        if (dt > 0.0) avg_fps = (double)frames_total / dt;
    }

    int w=0, h=0; int fr_n=0, fr_d=1; const char *fmt = NULL;
    if (g_gst.decoder) {
        GstPad *dp = gst_element_get_static_pad(g_gst.decoder, "src");
        if (dp) {
            GstCaps *caps = gst_pad_get_current_caps(dp);
            if (caps && !gst_caps_is_empty(caps)) {
                const GstStructure *s = gst_caps_get_structure(caps, 0);
                if (s) {
                    gst_structure_get_int(s, "width", &w);
                    gst_structure_get_int(s, "height", &h);
                    gst_structure_get_fraction(s, "framerate", &fr_n, &fr_d);
                    fmt = gst_structure_get_string(s, "format");
                }
            }
            if (caps) gst_caps_unref(caps);
            gst_object_unref(dp);
        }
    }
    if (w>0 && h>0) {
        if (fmt)
            g_print("decoder: %dx%d %s  fr=%.3f  fps(inst)=%.2f fps(avg)=%.2f  frames=%" PRIu64 "\n",
                    w, h, fmt, (fr_d? (double)fr_n/fr_d : 0.0), inst_fps, avg_fps, frames_total);
            else
                g_print("decoder: %dx%d  fr=%.3f  fps(inst)=%.2f fps(avg)=%.2f  frames=%" PRIu64 "\n",
                        w, h, (fr_d? (double)fr_n/fr_d : 0.0), inst_fps, avg_fps, frames_total);
    } else {
        g_print("decoder: fps(inst)=%.2f fps(avg)=%.2f  frames=%" PRIu64 " (caps not negotiated yet)\n",
                inst_fps, avg_fps, frames_total);
    }

    // QoS table (per-element)
    qos_print();
}

// ---------------- relay thread ----------------
static gpointer relay_thread_fn(gpointer data) {
    RelayCtx *rc = (RelayCtx*)data;
    rc->running = 1;

    // IPv4 UDP socket
    int in_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (in_fd < 0) { perror("relay socket in"); rc->running = 0; return NULL; }

    // Bind 0.0.0.0:listen_port
    struct sockaddr_in bind_addr = {0};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = htons((uint16_t)rc->listen_port);
    if (bind(in_fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("relay bind"); close(in_fd); rc->running = 0; return NULL;
    }

    // Nonblocking stdin for commands
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);

    g_print("Relay: listening on UDP %d (push to appsrc). Commands: l=list, n=next, s <i>, stats, q=quit\n",
            rc->listen_port);

    unsigned char buf[RELAY_BUF_SIZE];
    struct pollfd fds[2];
    fds[0].fd = in_fd;         fds[0].events = POLLIN;
    fds[1].fd = STDIN_FILENO;  fds[1].events = POLLIN;

    while (rc->running) {
        int pr = poll(fds, 2, 200);
        if (pr < 0) {
            if (errno == EINTR) continue;
            perror("relay poll"); break;
        }

        // stdin
        if (pr > 0 && (fds[1].revents & POLLIN)) {
            char line[256];
            ssize_t n = read(STDIN_FILENO, line, sizeof(line)-1);
            if (n > 0) {
                line[n] = 0;
                for (ssize_t i=n-1; i>=0 && (line[i]=='\n'||line[i]=='\r'); --i) line[i]=0;

                if (!strcmp(line, "q")) {
                    rc->running = 0; break;
                } else if (!strcmp(line, "l")) {
                    relay_print_sources(rc);
                } else if (!strcmp(line, "n")) {
                    if (rc->sources_count > 0) {
                        rc->selected_idx = (rc->selected_idx + 1) % rc->sources_count;
                        char s[64]; addr_to_str(&rc->sources[rc->selected_idx].addr, s, sizeof(s));
                        g_print("Relay: selected next source: [%d] %s\n", rc->selected_idx, s);
                    } else g_print("Relay: no sources yet.\n");
                } else if (!strncmp(line, "s ", 2)) {
                    int idx = -1;
                    if (sscanf(line+2, "%d", &idx) == 1) {
                        if (idx >= 0 && idx < rc->sources_count && rc->sources[idx].in_use) {
                            rc->selected_idx = idx;
                            char s[64]; addr_to_str(&rc->sources[idx].addr, s, sizeof(s));
                            g_print("Relay: selected [%d] %s\n", idx, s);
                        } else g_print("Relay: bad index.\n");
                    } else g_print("Usage: s <index>\n");
                } else if (!strcmp(line, "stats")) {
                    stats_print(rc, &g_gst);
                } else {
                    g_print("Commands: l, n, s <i>, stats, q\n");
                }
                fflush(stdout);
            }
        }

        // UDP input
        if (pr > 0 && (fds[0].revents & POLLIN)) {
            struct sockaddr_in from = {0};
            socklen_t fromlen = sizeof(from);
            ssize_t r = recvfrom(in_fd, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
            if (r < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                perror("relay recvfrom"); continue;
            }
            int idx = -1;
            bool is_new = relay_add_or_find(rc, &from, fromlen, &idx);
            Source *src = NULL;
            if (idx >= 0 && idx < rc->sources_count) src = &rc->sources[idx];

            if (is_new) {
                char s[64]; addr_to_str(&from, s, sizeof(s));
                g_print("Relay: discovered source: [%d] %s\n", idx, s);
                if (rc->selected_idx < 0) {
                    rc->selected_idx = idx;
                    g_print("Relay: selected first source: [%d] %s\n", idx, s);
                }
            }

            if (src) {
                src->pkts++;
                src->bytes += (uint64_t)r;
                src->last_seen_us = g_get_monotonic_time();
                // RTP telemetry (safe even if not RTP; header check inside)
                rtp_update_stats(src, buf, (size_t)r, g_gst.clockrate);
            }

            if (rc->push_enabled && rc->selected_idx >= 0 && idx == rc->selected_idx && rc->appsrc) {
                GstBuffer *gbuf = gst_buffer_new_allocate(NULL, (gsize)r, NULL);
                if (gbuf) {
                    GstMapInfo m;
                    if (gst_buffer_map(gbuf, &m, GST_MAP_WRITE)) {
                        memcpy(m.data, buf, (size_t)r);
                        gst_buffer_unmap(gbuf, &m);
                    }
                    GST_BUFFER_FLAG_SET(gbuf, GST_BUFFER_FLAG_LIVE);

                    GstFlowReturn fr = gst_app_src_push_buffer(rc->appsrc, gbuf);
                    if (fr == GST_FLOW_OK) {
                        if (src) { src->fwd_pkts++; src->fwd_bytes += (uint64_t)r; }
                    } else {
                        const char *reason = "OTHER";
                        switch (fr) {
                            case GST_FLOW_FLUSHING: reason = "FLUSHING"; break;
                            case GST_FLOW_NOT_LINKED: reason = "NOT_LINKED"; break;
                            case GST_FLOW_EOS: reason = "EOS"; break;
                            default: break;
                        }
                        g_printerr("appsrc push dropped: %s\n", reason);
                    }
                }
            }
        }
    }

    close(in_fd);
    rc->running = 0;
    return NULL;
}

// --------------- GStreamer side ---------------
static gboolean bus_cb(GstBus *bus, GstMessage *msg, gpointer user_data) {
    (void)bus;
    GstCtx *gc = (GstCtx*)user_data;
    switch (GST_MESSAGE_TYPE(msg)) {
        case GST_MESSAGE_QOS:
            qos_update_from_msg(msg);
            break;
        case GST_MESSAGE_ERROR: {
            GError *err = NULL; gchar *dbg = NULL;
            gst_message_parse_error(msg, &err, &dbg);
            g_printerr("ERROR: %s\n", err ? err->message : "unknown");
            if (dbg) g_printerr("DEBUG: %s\n", dbg);
            if (err) g_error_free(err);
            g_free(dbg);
            g_relay.running = 0;
            if (gc->loop) g_main_loop_quit(gc->loop);
            break;
        }
        case GST_MESSAGE_EOS:
            g_print("EOS\n");
            g_relay.running = 0;
            if (gc->loop) g_main_loop_quit(gc->loop);
            break;
        default: break;
    }
    return TRUE;
}

// appsrc callbacks: gate pushing precisely when downstream wants data.
static void on_need_data(GstAppSrc *src, guint length, gpointer user_data) {
    (void)src; (void)length; (void)user_data;
    g_relay.push_enabled = 1;
}
static void on_enough_data(GstAppSrc *src, gpointer user_data) {
    (void)src; (void)user_data;
    g_relay.push_enabled = 0;
}

// decoder src probe: count frames for FPS stats
static GstPadProbeReturn dec_src_probe(GstPad *pad, GstPadProbeInfo *info, gpointer user_data) {
    (void)pad; (void)user_data;
    if (GST_PAD_PROBE_INFO_TYPE(info) & GST_PAD_PROBE_TYPE_BUFFER) {
        gint64 now_us = g_get_monotonic_time();
        g_mutex_lock(&g_dec.lock);
        if (g_dec.first_us == 0) g_dec.first_us = now_us;
        g_dec.frames_total++;
        g_mutex_unlock(&g_dec.lock);
    }
    return GST_PAD_PROBE_OK;
}

static gboolean build_pipeline(GstCtx *gc) {
    gc->appsrc_e = gst_element_factory_make("appsrc", "src");
    gc->queue0   = gst_element_factory_make("queue", "q0");
    gc->jbuf     = gst_element_factory_make("rtpjitterbuffer", "jbuf");
    gc->depay    = gst_element_factory_make("rtph265depay", "depay");
    gc->decoder  = gst_element_factory_make("vaapih265dec", "dec");
    if (!gc->decoder) {
        gc->decoder = gst_element_factory_make("avdec_h265", "dec");
        if (gc->decoder) g_printerr("Using avdec_h265 (software) fallback.\n");
    }
    gc->sink     = gst_element_factory_make("xvimagesink", "xvsink");
    GstElement *capsf  = gst_element_factory_make("capsfilter", "capsf");

    if (!gc->appsrc_e || !capsf || !gc->queue0 || !gc->jbuf || !gc->depay || !gc->decoder || !gc->sink) {
        g_printerr("Failed to create one or more GStreamer elements.\n");
        return FALSE;
    }

    gc->pipeline = gst_pipeline_new("udp-h265-viewer");
    if (!gc->pipeline) { g_printerr("Failed to create pipeline.\n"); return FALSE; }

    // CAPS (include media=video)
    gchar *caps_str = g_strdup_printf(
        "application/x-rtp,media=video,encoding-name=H265,payload=%d,clock-rate=%d",
        gc->payload, gc->clockrate);
    GstCaps *caps = gst_caps_from_string(caps_str);
    g_free(caps_str);
    if (!caps) { g_printerr("Failed to build RTP caps.\n"); return FALSE; }

    // appsrc config
    g_object_set(gc->appsrc_e,
                 "is-live", TRUE,
                 "format", GST_FORMAT_BYTES,     // 1 buffer = 1 RTP datagram
                 "block", FALSE,                 // favor latency (drop when full)
    "max-bytes", (guint64)(2*1024*1024),
                 "stream-type", GST_APP_STREAM_TYPE_STREAM,
                 NULL);

    // Set caps via API so a CAPS event is sent
    gst_app_src_set_caps(GST_APP_SRC(gc->appsrc_e), caps);
    // capsfilter with same caps (defensive)
    g_object_set(capsf, "caps", caps, NULL);
    gst_caps_unref(caps);

    // Low-latency queue (drop oldest when downstream blocks)
    g_object_set(gc->queue0,
                 "leaky", 2, // downstream
                 "max-size-buffers", 200,
                 "max-size-bytes", 0,
                 "max-size-time", (guint64)200000000, // 200ms
                 NULL);

    // jitterbuffer
    g_object_set(gc->jbuf, "latency", 8, NULL);

    // sink sync
    g_object_set(gc->sink, "sync", gc->sync, NULL);

    // Assemble
    gst_bin_add_many(GST_BIN(gc->pipeline),
                     gc->appsrc_e, capsf, gc->queue0, gc->jbuf, gc->depay, gc->decoder, gc->sink, NULL);
    if (!gst_element_link_many(gc->appsrc_e, capsf, gc->queue0, gc->jbuf, gc->depay, gc->decoder, gc->sink, NULL)) {
        g_printerr("Pipeline link failed.\n");
        return FALSE;
    }

    // Decoder src probe for FPS
    GstPad *dec_src = gst_element_get_static_pad(gc->decoder, "src");
    if (dec_src) {
        gst_pad_add_probe(dec_src, GST_PAD_PROBE_TYPE_BUFFER, dec_src_probe, NULL, NULL);
        gst_object_unref(dec_src);
    }

    // Bus
    GstBus *bus = gst_element_get_bus(gc->pipeline);
    gst_bus_add_watch(bus, bus_cb, gc);
    gst_object_unref(bus);

    // Appsrc callbacks to gate pushing precisely
    GstAppSrcCallbacks cbs = { on_need_data, on_enough_data, NULL };
    gst_app_src_set_callbacks(GST_APP_SRC(gc->appsrc_e), &cbs, NULL, NULL);

    return TRUE;
}

// --------------- glue ---------------
static void handle_sigint(int sig) {
    (void)sig;
    g_relay.running = 0;
    if (g_gst.loop) g_main_loop_quit(g_gst.loop);
}

static void usage(const char *argv0) {
    g_printerr(
        "Usage: %s [--listen-port N (5600)] [--payload PT (97)] [--clockrate Hz (90000)] [--no-sync]\n",
               argv0);
}

int main(int argc, char **argv) {
    // Defaults
    g_relay.listen_port = 5600;
    g_relay.selected_idx = -1;
    g_relay.push_enabled = 0;

    g_gst.payload   = 97;
    g_gst.clockrate = 90000;
    g_gst.sync      = TRUE;

    g_mutex_init(&g_dec.lock);
    g_dec.frames_total = 0; g_dec.first_us = 0; g_dec.prev_frames = 0; g_dec.prev_us = 0;

    qos_db_init(&g_qos);

    // Args (pre-gst)
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--listen-port") && i+1 < argc) {
            g_relay.listen_port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--payload") && i+1 < argc) {
            g_gst.payload = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--clockrate") && i+1 < argc) {
            g_gst.clockrate = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--no-sync")) {
            g_gst.sync = FALSE;
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]); return 0;
        }
    }

    gst_init(&argc, &argv);
    if (!build_pipeline(&g_gst)) return 1;

    // Provide appsrc to relay
    g_relay.appsrc = GST_APP_SRC(g_gst.appsrc_e);

    // Start relay thread
    g_relay.thread = g_thread_new("udp-relay", relay_thread_fn, &g_relay);
    if (!g_relay.thread) {
        g_printerr("Failed to start relay thread.\n");
        gst_object_unref(g_gst.pipeline);
        return 1;
    }

    // Ctrl-C
    signal(SIGINT, handle_sigint);

    g_print("Viewer: appsrc pipeline starting. Waiting for UDP on %d…\n", g_relay.listen_port);

    // PLAY and main loop
    gst_element_set_state(g_gst.pipeline, GST_STATE_PLAYING);
    g_gst.loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(g_gst.loop);

    // Teardown: stop relay first
    g_relay.push_enabled = 0;
    g_relay.running = 0;
    if (g_relay.thread) g_thread_join(g_relay.thread);

    gst_element_set_state(g_gst.pipeline, GST_STATE_NULL);
    gst_object_unref(g_gst.pipeline);
    if (g_gst.loop) g_main_loop_unref(g_gst.loop);

    // QoS DB cleanup
    qos_db_clear(&g_qos);
    if (g_qos.table) { g_hash_table_destroy(g_qos.table); g_qos.table = NULL; }

    return 0;
}
