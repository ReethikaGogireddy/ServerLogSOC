import { useEffect, useMemo, useState } from "react";
import { NavLink } from "react-router-dom";
import { UserButton } from "@clerk/clerk-react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
} from "recharts";
import "./Analytics.css";

type PageItem = { path: string; count: number };
type IpItem = { ip: string; count: number };

type EventItem = {
  time?: string;
  ip?: string;
  type: string;
  severity: string;
  reason: string;
  confidence: number;
  count_404?: number;
  unique_paths?: number;
};

type ReferrerItem = {
  domain: string;
  count: number;
  virustotal?: {
    domain: string;
    status: string;
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
  };
};

type AnalyticsData = {
  most_accessed_pages: PageItem[];
  least_accessed_pages: PageItem[];
  top_ips: IpItem[];
  unique_ip_count: number;
  most_active_ip: IpItem | null;
  status_breakdown: Record<string, number>;
  device_breakdown: Record<string, number>;
  top_referrers: ReferrerItem[];
  unique_referrer_count: number;
  timeline: { time: string; count: number }[];
  event_feed: EventItem[];
  attack_distribution: { name: string; value: number }[];
};

const COLORS = [
  "#4f8cff",
  "#22c55e",
  "#f59e0b",
  "#ef4444",
  "#a855f7",
  "#06b6d4",
];

function Analytics() {
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [message, setMessage] = useState("Loading analytics...");
  const [timelineOpen, setTimelineOpen] = useState(false);

  useEffect(() => {
    const fetchAnalytics = async () => {
      try {
        const res = await fetch(`${import.meta.env.VITE_API_URL}/analyze`);
        const json = await res.json();

        if (res.ok && json.status === "success") {
          setData(json.analysis);
          setMessage("");
        } else {
          setMessage(json.message || "Failed to load analytics.");
        }
      } catch {
        setMessage("Could not connect to backend.");
      }
    };

    fetchAnalytics();
  }, []);

  const statusChartData = useMemo(
    () =>
      data
        ? Object.entries(data.status_breakdown).map(([name, value]) => ({
            name,
            value,
          }))
        : [],
    [data],
  );

  const deviceChartData = useMemo(
    () =>
      data
        ? Object.entries(data.device_breakdown).map(([name, value]) => ({
            name,
            value,
          }))
        : [],
    [data],
  );

  const topAlerts = data?.event_feed.slice(0, 3) || [];
  const topPages = data?.most_accessed_pages.slice(0, 5) || [];
  const topIps = data?.top_ips.slice(0, 5) || [];
  const topReferrers = data?.top_referrers.slice(0, 5) || [];

  return (
    <div className="analytics-page">
      <nav className="topbar">
        <div className="brand">
          <h1>ServerLogSOC</h1>
          <p>SOC log analysis dashboard</p>
        </div>

        <div className="nav-links">
          <NavLink
            to="/dashboard"
            className={({ isActive }) =>
              isActive ? "nav-link active" : "nav-link"
            }
          >
            Upload
          </NavLink>
          <NavLink
            to="/analytics"
            className={({ isActive }) =>
              isActive ? "nav-link active" : "nav-link"
            }
          >
            Analytics
          </NavLink>
          <UserButton />
        </div>
      </nav>

      <main className="analytics-main">
        <div className="page-header">
          <div>
            <h2>Analytics</h2>
            <p>Start with alerts, then drill into traffic and behaviour.</p>
          </div>
        </div>

        {message && <div className="notice">{message}</div>}

        {data && (
          <>
            <section className="summary-grid">
              <div className="summary-card">
                <span>SUSPICIOUS EVENTS</span>
                <strong>{data.event_feed.length}</strong>
              </div>

              <div className="summary-card">
                <span>UNIQUE IPS</span>
                <strong>{data.unique_ip_count}</strong>
              </div>

              <div className="summary-card">
                <span>MOST ACTIVE IP</span>
                <strong>{data.most_active_ip?.ip || "N/A"}</strong>
              </div>

              <div className="summary-card">
                <span>UNIQUE REFERRER DOMAINS</span>
                <strong>{data.unique_referrer_count}</strong>
              </div>
            </section>

            <section className="panel alerts-panel">
              <div className="panel-head">
                <h3>Top alerts</h3>
                <span>Most important first</span>
              </div>

              <div className="alert-list">
                {topAlerts.map((event, idx) => (
                  <div key={idx} className={`alert-item ${event.severity}`}>
                    <div className="alert-top">
                      <strong>{event.type}</strong>
                      <span>{Math.round(event.confidence * 100)}%</span>
                    </div>
                    <p>{event.reason}</p>
                    <small>
                      {event.count_404
                        ? `${event.count_404} 404 responses`
                        : ""}
                      {event.unique_paths
                        ? ` across ${event.unique_paths} paths`
                        : ""}
                      {event.time ? ` • ${event.time}` : ""}
                      {event.ip ? ` • ${event.ip}` : ""}
                    </small>
                  </div>
                ))}
              </div>
            </section>

            <section className="panel timeline-panel">
              <div className="panel-head">
                <h3>Traffic timeline</h3>
                <span>Volume over time</span>
              </div>
              <section className="panel">
                <div
                  className="panel-head collapsible"
                  onClick={() => setTimelineOpen(!timelineOpen)}
                >
                  <h3>Event Timeline</h3>
                  <div className="timeline-toggle-right">
                    <span className="event-count">
                      {data.event_feed.filter((e) => e.time).length} events
                    </span>
                    <span
                      className={`timeline-chevron ${timelineOpen ? "open" : ""}`}
                    >
                      ▼
                    </span>
                  </div>
                </div>

                {timelineOpen && (
                  <div className="alert-list">
                    {data.event_feed
                      .filter((e) => e.time)
                      .sort((a, b) => a.time!.localeCompare(b.time!))
                      .map((event, idx) => (
                        <div
                          key={idx}
                          className={`alert-item ${event.severity}`}
                        >
                          <div className="alert-top">
                            <strong>{event.type}</strong>
                            <span>{Math.round(event.confidence * 100)}%</span>
                          </div>
                          <p>{event.reason}</p>
                          <small>
                            {event.time
                              ? new Date(event.time).toLocaleString()
                              : "No timestamp"}
                            {event.ip ? ` • ${event.ip}` : ""}
                          </small>
                        </div>
                      ))}

                    {data.event_feed.filter((e) => e.time).length === 0 && (
                      <p style={{ color: "#7f8aa3" }}>
                        No timestamped events found.
                      </p>
                    )}
                  </div>
                )}
              </section>

              <div className="chart-box timeline-box">
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={data.timeline}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis
                      dataKey="time"
                      tickFormatter={(t) =>
                        new Date(t).toLocaleString("en-US", {
                          month: "short",
                          day: "numeric",
                          hour: "2-digit",
                        })
                      }
                      tick={{ fill: "#7f8aa3", fontSize: 11 }}
                    />
                    <YAxis />
                    <Tooltip
                      labelFormatter={(t) =>
                        new Date(t).toLocaleString("en-US", {
                          month: "short",
                          day: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                        })
                      }
                    />
                    <Bar dataKey="count" fill="#4f8cff" radius={[6, 6, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </section>

            <section className="stats-grid">
              <div className="panel pie-panel">
                <div className="panel-head">
                  <h3>HTTP Response Status breakdown</h3>
                  <span>Allowed vs blocked vs Others </span>
                </div>
                <div>
                  <div className="chart-box">
                    <ResponsiveContainer width="100%" height={280}>
                      <PieChart>
                        <Pie
                          data={statusChartData}
                          dataKey="value"
                          nameKey="name"
                          outerRadius={95}
                          innerRadius={55}
                          paddingAngle={3}
                          label
                        >
                          {statusChartData.map((_, index) => (
                            <Cell
                              key={index}
                              fill={COLORS[index % COLORS.length]}
                            />
                          ))}
                        </Pie>
                        <Tooltip />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>

              <div className="panel pie-panel">
                <div className="panel-head">
                  <h3>Attack distribution</h3>
                  <span>Types of detected attacks</span>
                </div>

                <div className="chart-box">
                  <ResponsiveContainer width="100%" height={280}>
                    <PieChart>
                      <Pie
                        data={data.attack_distribution}
                        dataKey="value"
                        nameKey="name"
                        outerRadius={95}
                        innerRadius={55}
                        paddingAngle={3}
                        label
                      >
                        {data.attack_distribution.map((_, index) => (
                          <Cell
                            key={index}
                            fill={COLORS[index % COLORS.length]}
                          />
                        ))}
                      </Pie>
                      <Tooltip />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="panel pie-panel">
                <div className="panel-head">
                  <h3>Device breakdown</h3>
                  <span>Bot vs desktop vs mobile</span>
                </div>

                <div className="chart-box">
                  <ResponsiveContainer width="100%" height={280}>
                    <PieChart>
                      <Pie
                        data={deviceChartData}
                        dataKey="value"
                        nameKey="name"
                        outerRadius={95}
                        innerRadius={55}
                        paddingAngle={3}
                        label
                      >
                        {deviceChartData.map((_, index) => (
                          <Cell
                            key={index}
                            fill={COLORS[index % COLORS.length]}
                          />
                        ))}
                      </Pie>
                      <Tooltip />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </section>
            <section className="bottom-grid">
              <div className="panel list-panel">
                <div className="panel-head">
                  <h3>Top referrers</h3>
                  <span>External domains</span>
                </div>

                <div className="mini-list">
                  {topReferrers.map((item, idx) => {
                    const isMalicious =
                      item.virustotal &&
                      (item.virustotal.malicious > 0 ||
                        item.virustotal.suspicious > 0);
                    const threatLevel =
                      (item.virustotal?.malicious ?? 0) > 0
                        ? "malicious"
                        : "suspicious";

                    return (
                      <div key={idx} className="list-row">
                        <span
                          className={isMalicious ? `threat-${threatLevel}` : ""}
                        >
                          {item.domain}
                          {isMalicious && (
                            <span className="threat-badge">
                              ⚠️
                              {(item.virustotal?.malicious ?? 0) > 0
                                ? "Malicious"
                                : "Suspicious"}
                            </span>
                          )}
                        </span>
                        <span>
                          <strong
                            className={
                              (item.virustotal?.malicious ?? 0) > 0
                                ? "threat-malicious"
                                : (item.virustotal?.suspicious ?? 0) > 0
                                  ? "threat-suspicious"
                                  : ""
                            }
                          >
                            {item.count.toLocaleString()}
                          </strong>
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="panel list-panel">
                <div className="panel-head">
                  <h3>Top pages</h3>
                  <span>Most accessed paths</span>
                </div>

                <div className="mini-list">
                  {topPages.map((item, idx) => (
                    <div key={idx} className="list-row">
                      <span>{item.path}</span>
                      <strong>{item.count.toLocaleString()}</strong>
                    </div>
                  ))}
                </div>
              </div>

              <div className="panel list-panel">
                <div className="panel-head">
                  <h3>Top IPs</h3>
                  <span>Most active sources</span>
                </div>

                <div className="mini-list">
                  {topIps.map((item, idx) => (
                    <div key={idx} className="list-row">
                      <span>{item.ip}</span>
                      <strong className={idx === 0 ? "highlight" : ""}>
                        {item.count.toLocaleString()}
                      </strong>
                    </div>
                  ))}
                </div>
              </div>
            </section>
          </>
        )}
      </main>
    </div>
  );
}

export default Analytics;
