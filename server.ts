import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  try {
    const app = express();
    const PORT = 3000;

  app.use(express.json());

  // Simple request logger
  app.use((req, res, next) => {
    if (req.url.startsWith('/api')) {
      console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    }
    next();
  });

  // Mock database of IoCs
  let iocs = [
    {
      value: '45.33.2.1',
      type: 'IP',
      reputation: 'Malicious',
      lastSeen: new Date().toISOString(),
      tags: ['Ransomware', 'C2 Server']
    },
    {
      value: 'hr-portal-secure.com',
      type: 'Domain',
      reputation: 'Suspicious',
      lastSeen: new Date().toISOString(),
      tags: ['Phishing', 'Credential Harvesting']
    },
    {
      value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      type: 'Hash',
      reputation: 'Malicious',
      lastSeen: new Date().toISOString(),
      tags: ['LockBit', 'Trojan']
    }
  ];

  // System Logs and Alerts
  let logs: { id: string; timestamp: string; level: 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL'; message: string; source: string }[] = [];
  let alerts: { id: string; timestamp: string; severity: 'Critical' | 'High' | 'Medium'; message: string; type: string }[] = [];
  let attackMapData: { id: string; source: { lat: number; lng: number }; target: { lat: number; lng: number }; type: string; country?: string }[] = [];
  let isUnderAttack = false;
  const ipCache = new Map<string, { lat: number; lng: number; country: string }>();
  let correlations: { id: string; timestamp: string; title: string; description: string; severity: 'Critical' | 'High' | 'Medium'; relatedIds: string[]; pattern: string }[] = [];
  let networkStats = {
    bandwidth: { inbound: 45.2, outbound: 12.8 },
    packets: { inbound: 12500, outbound: 8400 },
    protocols: [
      { name: 'TCP', value: 65 },
      { name: 'UDP', value: 25 },
      { name: 'ICMP', value: 5 },
      { name: 'Other', value: 5 }
    ],
    topTalkers: [
      { ip: '10.0.0.45', traffic: '1.2 GB', type: 'Internal' },
      { ip: '10.0.0.12', traffic: '850 MB', type: 'Internal' },
      { ip: '45.33.2.1', traffic: '420 MB', type: 'External' },
      { ip: '192.168.1.105', traffic: '310 MB', type: 'Internal' },
      { ip: '8.8.8.8', traffic: '150 MB', type: 'External' }
    ]
  };

  const threatActors = [
    {
      id: 'APT-28',
      name: 'Fancy Bear',
      aliases: ['APT28', 'Pawn Storm', 'Sofacy Group', 'Sednit', 'STRONTIUM'],
      origin: 'Russia',
      targetSectors: ['Government', 'Military', 'Energy', 'Media'],
      motivations: ['Espionage', 'Political Influence'],
      ttps: [
        { id: 'T1566.001', name: 'Spearphishing Attachment', description: 'Sending malicious attachments via email to gain initial access.', mitreUrl: 'https://attack.mitre.org/techniques/T1566/001/' },
        { id: 'T1203', name: 'Exploitation for Client Execution', description: 'Exploiting software vulnerabilities on client systems.', mitreUrl: 'https://attack.mitre.org/techniques/T1203/' },
        { id: 'T1071.001', name: 'Web Protocols', description: 'Using standard web protocols for command and control communication.', mitreUrl: 'https://attack.mitre.org/techniques/T1071/001/' },
        { id: 'T1003', name: 'OS Credential Dumping', description: 'Extracting account credentials from operating systems.', mitreUrl: 'https://attack.mitre.org/techniques/T1003/' }
      ],
      description: 'A highly sophisticated threat actor group linked to the Russian GRU. Known for high-profile attacks on government and political organizations worldwide.',
      lastActive: '2026-03-15'
    },
    {
      id: 'APT-41',
      name: 'Double Dragon',
      aliases: ['APT41', 'BARIUM', 'Winnti Group', 'Wicked Panda'],
      origin: 'China',
      targetSectors: ['Technology', 'Healthcare', 'Gaming', 'Finance'],
      motivations: ['Espionage', 'Financial Gain'],
      ttps: [
        { id: 'T1195.002', name: 'Supply Chain Compromise', description: 'Compromising software updates or distribution channels.', mitreUrl: 'https://attack.mitre.org/techniques/T1195/002/' },
        { id: 'T1553.002', name: 'Code Signing', description: 'Using stolen or fraudulent certificates to sign malicious code.', mitreUrl: 'https://attack.mitre.org/techniques/T1553/002/' },
        { id: 'T1190', name: 'Exploit Public-Facing Application', description: 'Exploiting vulnerabilities in internet-facing software.', mitreUrl: 'https://attack.mitre.org/techniques/T1190/' },
        { id: 'T1505.003', name: 'Web Shell', description: 'Deploying web shells to maintain persistent access to servers.', mitreUrl: 'https://attack.mitre.org/techniques/T1505/003/' }
      ],
      description: 'A prolific Chinese state-sponsored group that conducts both espionage and financially motivated cybercrime. They are known for their technical skill and diverse target set.',
      lastActive: '2026-03-18'
    },
    {
      id: 'LAZARUS',
      name: 'Lazarus Group',
      aliases: ['Hidden Cobra', 'Guardians of Peace', 'Zinc'],
      origin: 'North Korea',
      targetSectors: ['Finance', 'Cryptocurrency', 'Critical Infrastructure', 'Entertainment'],
      motivations: ['Financial Gain', 'Destruction', 'Espionage'],
      ttps: [
        { id: 'T1486', name: 'Data Encrypted for Impact', description: 'Using ransomware or wipers to disrupt operations or extort money.', mitreUrl: 'https://attack.mitre.org/techniques/T1486/' },
        { id: 'T1566.002', name: 'Spearphishing Link', description: 'Sending malicious links via email or social media.', mitreUrl: 'https://attack.mitre.org/techniques/T1566/002/' },
        { id: 'T1059.003', name: 'Windows Command Shell', description: 'Using cmd.exe to execute malicious commands.', mitreUrl: 'https://attack.mitre.org/techniques/T1059/003/' },
        { id: 'T1547.001', name: 'Registry Run Keys / Startup Folder', description: 'Achieving persistence by adding entries to startup locations.', mitreUrl: 'https://attack.mitre.org/techniques/T1547/001/' }
      ],
      description: 'A North Korean state-sponsored group responsible for some of the most destructive and financially significant cyberattacks in history, including the Sony Pictures hack and the WannaCry ransomware attack.',
      lastActive: '2026-03-19'
    }
  ];

  const updateNetworkStats = () => {
    const multiplier = isUnderAttack ? 5 : 1;
    networkStats = {
      ...networkStats,
      bandwidth: {
        inbound: Number((40 + Math.random() * 10 * multiplier).toFixed(1)),
        outbound: Number((10 + Math.random() * 5 * multiplier).toFixed(1))
      },
      packets: {
        inbound: Math.floor((12000 + Math.random() * 2000) * multiplier),
        outbound: Math.floor((8000 + Math.random() * 1000) * multiplier)
      }
    };
  };

  setInterval(updateNetworkStats, 3000);

  const runCorrelationEngine = () => {
    const newCorrelations: typeof correlations = [];
    
    // Pattern 1: IoC Match in Logs
    iocs.forEach(ioc => {
      const matchingLogs = logs.filter(log => log.message.includes(ioc.value));
      if (matchingLogs.length > 0) {
        newCorrelations.push({
          id: `COR-${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
          timestamp: new Date().toISOString(),
          title: 'Known Malicious Indicator Detected',
          description: `Indicator ${ioc.value} (${ioc.tags.join(', ')}) was detected in system logs from ${matchingLogs[0].source}.`,
          severity: ioc.reputation === 'Malicious' ? 'Critical' : 'High',
          relatedIds: matchingLogs.map(l => l.id),
          pattern: 'IOC_MATCH'
        });
      }
    });

    // Pattern 2: Brute Force Attempt
    const authLogs = logs.filter(l => l.source === 'AuthService' && l.message.toLowerCase().includes('failed'));
    if (authLogs.length > 5) {
      newCorrelations.push({
        id: `COR-${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
        timestamp: new Date().toISOString(),
        title: 'Brute Force Pattern Identified',
        description: `Detected ${authLogs.length} failed login attempts within a short window. Possible automated credential stuffing.`,
        severity: 'High',
        relatedIds: authLogs.map(l => l.id),
        pattern: 'BRUTE_FORCE'
      });
    }

    // Pattern 3: Anomalous Data Access
    const dbLogs = logs.filter(l => l.source === 'DBProxy' && l.message.includes('executed'));
    const edgeLogs = logs.filter(l => l.source === 'EdgeFirewall' && l.message.includes('Connection established'));
    if (dbLogs.length > 10 && edgeLogs.length > 0) {
      newCorrelations.push({
        id: `COR-${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
        timestamp: new Date().toISOString(),
        title: 'Potential Data Exfiltration',
        description: 'High frequency of database queries followed by external network connections detected.',
        severity: 'Critical',
        relatedIds: [...dbLogs.map(l => l.id), ...edgeLogs.map(l => l.id)],
        pattern: 'DATA_EXFIL'
      });
    }

    correlations = [...newCorrelations, ...correlations].slice(0, 20);
  };

  setInterval(runCorrelationEngine, 5000);

  const fetchURLHausData = async () => {
    try {
      const response = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/');
      if (!response.ok) {
        console.warn(`URLHaus API returned ${response.status}`);
        return;
      }
      const data = await response.json();

      if (data.query_status === 'ok' && data.urls) {
        const newIocs = data.urls.slice(0, 10).map((url: any) => ({
          value: url.url,
          type: 'URL',
          reputation: 'Malicious',
          lastSeen: new Date().toISOString(),
          tags: url.tags || ['Malware'],
          source: 'URLHaus'
        }));
        iocs = [...newIocs, ...iocs].slice(0, 50);

        const newAlerts = data.urls.slice(0, 3).map((url: any) => ({
          id: `URLH-${url.id}`,
          timestamp: new Date().toISOString(),
          severity: 'High' as const,
          message: `Malicious URL detected: ${url.url_status}`,
          type: 'Malware URL',
          source: 'URLHaus'
        }));
        alerts = [...newAlerts, ...alerts].slice(0, 100);
      }
    } catch (error) {
      console.error('Error fetching URLHaus data:', error);
    }
  };

  const fetchFeodoTrackerData = async () => {
    try {
      const response = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.json');
      if (!response.ok) {
        console.warn(`Feodo Tracker API returned ${response.status}`);
        return;
      }
      const data = await response.json();

      if (Array.isArray(data)) {
        const newIocs = data.slice(0, 10).map((item: any) => ({
          value: item.ip_address,
          type: 'IP',
          reputation: 'Malicious',
          lastSeen: new Date().toISOString(),
          tags: [item.malware || 'Feodo'],
          source: 'Feodo Tracker'
        }));
        iocs = [...newIocs, ...iocs].slice(0, 50);

        const newAlerts = data.slice(0, 2).map((item: any, index: number) => ({
          id: `FEODO-${index}-${Date.now()}`,
          timestamp: new Date().toISOString(),
          severity: 'Critical' as const,
          message: `Feodo C2 IP detected: ${item.ip_address}`,
          type: 'C2 Server',
          source: 'Feodo Tracker'
        }));
        alerts = [...newAlerts, ...alerts].slice(0, 100);
      }
    } catch (error) {
      console.error('Error fetching Feodo Tracker data:', error);
    }
  };

  const fetchMISPData = async () => {
    try {
      // Fetching from a public MISP feed (CIRCL)
      const manifestRes = await fetch('https://misp.circl.lu/feeds/circl/manifest.json');
      if (!manifestRes.ok) {
        console.warn(`MISP Manifest API returned ${manifestRes.status}`);
        return;
      }
      const manifest = await manifestRes.json();
      
      const eventIds = Object.keys(manifest).slice(0, 3);
      const newIocs: any[] = [];
      const newAlerts: any[] = [];

      for (const id of eventIds) {
        try {
          const eventRes = await fetch(`https://misp.circl.lu/feeds/circl/${id}.json`);
          if (!eventRes.ok) continue;
          const eventData = await eventRes.json();
          
          if (eventData.Event) {
            const event = eventData.Event;
            newAlerts.push({
              id: `MISP-${event.id}`,
              timestamp: new Date().toISOString(),
              severity: event.threat_level_id === '1' ? 'Critical' : 'High',
              message: `MISP Event: ${event.info}`,
              type: 'MISP Event',
              source: 'CIRCL MISP'
            });

            if (event.Attribute) {
              event.Attribute.slice(0, 5).forEach((attr: any) => {
                if (['ip-src', 'ip-dst', 'domain', 'hostname', 'md5', 'sha1', 'sha256'].includes(attr.type)) {
                  newIocs.push({
                    value: attr.value,
                    type: attr.type.includes('ip') ? 'IP' : attr.type.includes('domain') || attr.type.includes('hostname') ? 'Domain' : 'Hash',
                    reputation: 'Malicious',
                    lastSeen: new Date().toISOString(),
                    tags: [attr.category],
                    source: 'CIRCL MISP'
                  });
                }
              });
            }
          }
        } catch (e) {
          console.error(`Error fetching MISP event ${id}:`, e);
        }
      }

      iocs = [...newIocs, ...iocs].slice(0, 50);
      alerts = [...newAlerts, ...alerts].slice(0, 100);
    } catch (error) {
      console.error('Error fetching MISP data:', error);
    }
  };

  const fetchRealThreatData = async () => {
    try {
      // Fetch from multiple sources
      await Promise.all([
        fetchURLHausData(),
        fetchFeodoTrackerData(),
        fetchMISPData(),
        (async () => {
          try {
            // Fetch recent IoCs from ThreatFox (Abuse.ch)
            const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
              method: 'POST',
              body: JSON.stringify({ query: 'get_recent', days: 1 })
            });
            if (!response.ok) {
              console.warn(`ThreatFox API returned ${response.status}`);
              return;
            }
            const data = await response.json();

            if (data.query_status === 'ok' && data.data) {
              const recentIoCs = data.data.slice(0, 10);
              const newAttacks = [];

              for (const ioc of recentIoCs) {
                // Add to global IoCs
                iocs = [{
                  value: ioc.ioc.split(':')[0],
                  type: ioc.ioc_type === 'ip:port' ? 'IP' : ioc.ioc_type === 'domain' ? 'Domain' : 'Hash',
                  reputation: 'Malicious',
                  lastSeen: new Date().toISOString(),
                  tags: [ioc.threat_type_desc],
                  source: 'ThreatFox'
                }, ...iocs].slice(0, 50);

                // Only process IPs or domains we can resolve/geolocate
                if (ioc.ioc_type === 'ip:port' || ioc.ioc_type === 'domain') {
                  const targetIp = ioc.ioc.split(':')[0];
                  
                  let geo = ipCache.get(targetIp);
                  if (!geo) {
                    try {
                      // Geolocate using ip-api.com (Free for non-commercial)
                      // Note: HTTPS is available for Pro users, but we'll try it as many free APIs have upgraded.
                      // If it fails, response.ok will be false and we'll catch it.
                      const geoRes = await fetch(`https://ip-api.com/json/${targetIp}?fields=status,lat,lon,country`);
                      if (geoRes.ok) {
                        const contentType = geoRes.headers.get("content-type");
                        if (contentType && contentType.includes("application/json")) {
                          const geoData = await geoRes.json();
                          if (geoData.status === 'success') {
                            geo = { lat: geoData.lat, lng: geoData.lon, country: geoData.country };
                            ipCache.set(targetIp, geo);
                          }
                        } else {
                          console.warn(`Geolocation API returned non-JSON response for ${targetIp}`);
                        }
                      } else {
                        console.warn(`Geolocation API returned ${geoRes.status} for ${targetIp}`);
                      }
                    } catch (e) {
                      console.error(`Error geolocating IP ${targetIp}:`, e);
                    }
                  }

                  if (geo) {
                    newAttacks.push({
                      id: ioc.id,
                      source: { lat: geo.lat, lng: geo.lng },
                      target: {
                        lat: 37.7749 + (Math.random() * 4 - 2), // US Target for visualization
                        lng: -122.4194 + (Math.random() * 4 - 2)
                      },
                      type: ioc.threat_type_desc || 'Malware',
                      country: geo.country
                    });
                  }
                }
              }

              if (newAttacks.length > 0) {
                attackMapData = [...newAttacks, ...attackMapData].slice(0, 20);
              }
            }
          } catch (e) {
            console.error('Error in ThreatFox fetch:', e);
          }
        })()
      ]);
    } catch (error) {
      console.error('Error fetching real threat data:', error);
      // Fallback to mock data if API fails
      generateMockAttack();
    }
  };

  const generateMockAttack = () => {
    const newAttack = {
      id: Math.random().toString(36).substr(2, 9),
      source: {
        lat: (Math.random() * 140) - 70,
        lng: (Math.random() * 360) - 180
      },
      target: {
        lat: 37.7749 + (Math.random() * 10 - 5),
        lng: -122.4194 + (Math.random() * 10 - 5)
      },
      type: ['DDoS', 'Malware', 'Phishing', 'Exploit'][Math.floor(Math.random() * 4)]
    };
    attackMapData = [newAttack, ...attackMapData.slice(0, 14)];
  };

  // Initial fetch and periodic updates
  fetchRealThreatData();
  setInterval(fetchRealThreatData, 60000); // Update every minute to respect rate limits

  const generateLog = () => {
    const levels: ('INFO' | 'WARN' | 'ERROR' | 'CRITICAL')[] = ['INFO', 'INFO', 'INFO', 'WARN', 'INFO'];
    const sources = ['AuthService', 'EdgeFirewall', 'DBProxy', 'APIGateway', 'Kernel'];
    const messages = [
      'User login successful',
      'Connection established from 10.0.0.45',
      'Database query executed in 12ms',
      'Heartbeat signal received',
      'Resource allocation optimized'
    ];

    if (isUnderAttack) {
      levels.push('ERROR', 'CRITICAL');
      messages.push('Multiple failed login attempts detected', 'Unauthorized access attempt blocked', 'High volumetric traffic on port 80');
    }

    const newLog = {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toISOString(),
      level: levels[Math.floor(Math.random() * levels.length)],
      source: sources[Math.floor(Math.random() * sources.length)],
      message: messages[Math.floor(Math.random() * messages.length)]
    };

    logs = [newLog, ...logs.slice(0, 99)];

    // Attack Detection Logic
    const recentCriticalLogs = logs.filter(l => (l.level === 'CRITICAL' || l.level === 'ERROR') && 
      (new Date().getTime() - new Date(l.timestamp).getTime() < 30000));
    
    // Random chance to start an attack if not already under one
    if (!isUnderAttack && Math.random() > 0.95) {
      isUnderAttack = true;
      const newAlert = {
        id: `AL-${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
        timestamp: new Date().toISOString(),
        severity: 'Critical' as const,
        message: 'SYSTEM UNDER ATTACK: Automated intrusion attempt detected',
        type: 'Intrusion'
      };
      alerts = [newAlert, ...alerts];
    }

    // Generate random High/Medium alerts more frequently
    if (Math.random() > 0.85) {
      const types = ['Phishing', 'Malware', 'Policy Violation', 'Anomalous Traffic'];
      const type = types[Math.floor(Math.random() * types.length)];
      const newAlert = {
        id: `AL-${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
        timestamp: new Date().toISOString(),
        severity: (Math.random() > 0.5 ? 'High' : 'Medium') as any,
        message: `Security Event: ${type} detected on endpoint ${Math.floor(Math.random() * 255)}`,
        type
      };
      alerts = [newAlert, ...alerts.slice(0, 49)];
    }

    if (recentCriticalLogs.length > 3 && !isUnderAttack) {
      isUnderAttack = true;
      const newAlert = {
        id: `AL-${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
        timestamp: new Date().toISOString(),
        severity: 'Critical' as const,
        message: 'SYSTEM UNDER ATTACK: Brute force / DDoS pattern detected',
        type: 'Intrusion'
      };
      alerts = [newAlert, ...alerts];
    } else if (recentCriticalLogs.length === 0 && isUnderAttack && Math.random() > 0.7) {
      isUnderAttack = false;
    }
  };

  setInterval(generateLog, 2000);

  // API Routes
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });

  app.get("/api/iocs", (req, res) => {
    res.json(iocs);
  });

  app.get("/api/logs", (req, res) => {
    res.json(logs);
  });

  app.get("/api/status", (req, res) => {
    res.json({ isUnderAttack, alertCount: alerts.length, latestAlert: alerts[0] || null });
  });

  app.get("/api/alerts", (req, res) => {
    res.json(alerts);
  });

  app.get("/api/attack-map", (req, res) => {
    res.json(attackMapData);
  });

  app.get("/api/correlations", (req, res) => {
    res.json(correlations);
  });

  app.get("/api/network-stats", (req, res) => {
    res.json(networkStats);
  });

  app.get("/api/threat-actors", (req, res) => {
    res.json(threatActors);
  });

  // Simulate new IoCs being added periodically
  setInterval(() => {
    const newIoC = {
      value: `192.168.1.${Math.floor(Math.random() * 255)}`,
      type: 'IP' as const,
      reputation: 'Suspicious' as const,
      lastSeen: new Date().toISOString(),
      tags: ['Anomalous Traffic', 'Scanner']
    };
    iocs = [newIoC, ...iocs.slice(0, 19)]; // Keep last 20
  }, 10000);

  // Catch-all for API routes that don't exist
  app.all("/api*", (req, res) => {
    console.warn(`404: API route not found: ${req.method} ${req.url}`);
    res.status(404).json({ error: "API route not found", path: req.url });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  // Global error handler to ensure JSON responses even on errors
  // This MUST be the last middleware in the stack
  app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error('Unhandled Error:', err);
    
    // If it's an API request, always return JSON
    if (req.url.startsWith('/api')) {
      return res.status(500).json({ 
        error: "Internal Server Error", 
        message: err.message || "An unexpected error occurred",
        path: req.url
      });
    }
    
    // Otherwise, let the default handler or Vite handle it
    next(err);
  });

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
  } catch (error) {
    console.error("CRITICAL: Error in startServer:", error);
  }
}

startServer().catch(err => {
  console.error("CRITICAL: Failed to start server:", err);
});
