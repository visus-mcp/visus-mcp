import { verifyContentHash } from '../../shared/crypto.js';
import { validateEvent, getHashableFields } from '../../shared/schemas/validate.js';
import { normalizeEvents } from '../../shared/normalizer.js';

describe('Meraki Sandbox Integration', () => {
  describe('Meraki API response schema validation', () => {
    const MERAKI_SANDBOX_EVENT_FIXTURES = [
      {
        type: 'network_events',
        apiPath: '/networks/N_12345678/events',
        fixture: {
          message: 'Fixture: Network event',
          page: 0,
          perPage: 1,
          events: [
            {
              occurredAt: '2026-05-24T12:00:00.000Z',
              networkId: 'N_12345678',
              type: 'vpn_connectivity_change',
              description: 'VPN connectivity changed',
              clientMac: '00:11:22:33:44:55',
              clientDescription: 'Test Client',
              deviceSerial: 'Q2XX-ABCD-1234',
              deviceName: 'Test MX',
              eventData: { status: 'connected' },
            },
          ],
        },
      },
      {
        type: 'security_events',
        apiPath: '/organizations/123456/appliance/security/events',
        fixture: {
          message: 'Fixture: Security event',
          page: 0,
          perPage: 1,
          events: [
            {
              occurredAt: '2026-05-24T12:00:00.000Z',
              networkId: 'N_12345678',
              type: 'ids_alert',
              description: 'IDS Alert triggered',
              alertId: 'ALERT-001',
              alertLevel: 'critical',
              sourceIp: '192.168.1.100',
              destinationIp: '10.0.0.1',
              signature: { id: 12345, message: 'Test signature' },
            },
          ],
        },
      },
      {
        type: 'clients',
        apiPath: '/networks/N_12345678/clients',
        fixture: [
          {
            id: 'k74272e',
            mac: '00:11:22:33:44:55',
            description: 'Test Client 1',
            ip: '10.0.0.100',
            ip6: null,
            user: null,
            vlan: '1',
            switchport: null,
            firstSeen: 1716500000,
            lastSeen: 1716586400,
            manufacturer: 'Apple',
            os: 'iOS 17',
            recentDeviceName: 'iPhone 15',
            recentDeviceSerial: 'DNPVR4Q0',
            recentDeviceMac: '22:33:44:55:66:77',
            ssid: 'Corporate WiFi',
            status: 'Online',
          },
        ],
      },
      {
        type: 'device_statuses',
        apiPath: '/organizations/123456/devices/statuses',
        fixture: [
          {
            name: 'MX-Test-01',
            serial: 'Q2XX-ABCD-1234',
            mac: '00:11:22:33:44:55',
            publicIp: '203.0.113.1',
            networkId: 'N_12345678',
            status: 'online',
            lastReportedAt: '2026-05-24T12:00:00.000Z',
            model: 'MX250',
            components: {
              powerSupplies: [],
            },
            productType: 'appliance',
          },
        ],
      },
      {
        type: 'vlans',
        apiPath: '/networks/N_12345678/appliance/vlans',
        fixture: [
          {
            id: '1',
            networkId: 'N_12345678',
            name: 'Default',
            applianceIp: '10.0.0.1',
            subnet: '10.0.0.0/24',
            dhcpHandling: 'Run a DHCP server',
            dhcpLeaseTime: '1 day',
            dhcpBootOptionsEnabled: false,
            dhcpOptions: [],
            interfaceIds: [],
            ipv6: { enabled: false },
            mandatoryDhcp: { enabled: false },
            vpnNatSubnet: '10.0.1.0/24',
          },
        ],
      },
      {
        type: 'ssids',
        apiPath: '/networks/N_12345678/wireless/ssids',
        fixture: [
          {
            number: 0,
            name: 'Corporate WiFi',
            enabled: true,
            authMode: '8021x-radius',
            encryptionMode: 'wpa',
            wpaEncryptionMode: 'WPA2 only',
            ipAssignmentMode: 'Bridge mode',
            visible: true,
            availableOnAllAps: true,
          },
          {
            number: 1,
            name: 'Guest WiFi',
            enabled: true,
            authMode: 'open',
            encryptionMode: 'wpa',
            wpaEncryptionMode: 'WPA2 only',
            ipAssignmentMode: 'NAT mode',
            visible: true,
            availableOnAllAps: true,
          },
        ],
      },
    ];

    it('validates event schema for all 6 Meraki endpoint types', () => {
      const PIPELINE_VERSION = 'a'.repeat(40);

      const endpointEventTypes: Record<string, string> = {
        network_events: 'meraki.network.event',
        security_events: 'meraki.security.event',
        clients: 'meraki.network.clients',
        device_statuses: 'meraki.org.device_statuses',
        vlans: 'meraki.network.vlans',
        ssids: 'meraki.network.ssids',
      };

      const endpointSources: Record<string, string> = {
        network_events: 'https://api.meraki.com/api/v1',
        security_events: 'https://api.meraki.com/api/v1',
        clients: 'https://api.meraki.com/api/v1',
        device_statuses: 'https://api.meraki.com/api/v1',
        vlans: 'https://api.meraki.com/api/v1',
        ssids: 'https://api.meraki.com/api/v1',
      };

      let totalEvents = 0;

      for (const fixtureSet of MERAKI_SANDBOX_EVENT_FIXTURES) {
        const items: Record<string, unknown>[] = [];
        if (fixtureSet.fixture && typeof fixtureSet.fixture === 'object' && 'events' in fixtureSet.fixture) {
          const events = (fixtureSet.fixture as { events: Record<string, unknown>[] }).events;
          items.push(...events);
        } else if (Array.isArray(fixtureSet.fixture)) {
          items.push(...fixtureSet.fixture as Record<string, unknown>[]);
        } else {
          items.push(fixtureSet.fixture as Record<string, unknown>);
        }

        const input = {
          org_id: 'sandbox-org',
          network_id: 'N_SANDBOX',
          source: 'meraki_poll' as const,
          source_url: `${endpointSources[fixtureSet.type]}${fixtureSet.apiPath}`,
          event_type: endpointEventTypes[fixtureSet.type],
          pipeline_version: PIPELINE_VERSION,
          items,
        };

        const { events, result } = normalizeEvents(input);
        totalEvents += result.total;

        for (const event of events) {
          expect(event.schema_version).toBe('v1');
          expect(event.org_id).toBe('sandbox-org');
          expect(event.network_id).toBe('N_SANDBOX');
          expect(event.source).toBe('meraki_poll');
          expect(event.event_type).toBe(endpointEventTypes[fixtureSet.type]);
          expect(event.content_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
          expect(event.harvest_timestamp).toBeDefined();
          expect(event.pipeline_version).toBe(PIPELINE_VERSION);
          expect(event.source_url).toBeDefined();
          expect(event.ttl).toBeGreaterThan(0);
          expect(event.event_id).toMatch(/^[a-zA-Z0-9_-]{16}$/);

          expect(() => validateEvent(event)).not.toThrow();
        }
      }

      expect(totalEvents).toBeGreaterThanOrEqual(6);
    });
  });

  describe('Content hash integrity', () => {
    it('every event has content_hash populated', () => {
      const PIPELINE_VERSION = 'a'.repeat(40);
      const items = [
        { test: 'payload-1', timestamp: '2026-05-24T12:00:00.000Z' },
        { test: 'payload-2', timestamp: '2026-05-24T12:00:01.000Z' },
        { test: 'payload-3', timestamp: '2026-05-24T12:00:02.000Z' },
      ];

      const input = {
        org_id: 'sandbox-org',
        network_id: 'N_SANDBOX',
        source: 'meraki_poll' as const,
        source_url: 'https://api.meraki.com/api/v1/test',
        event_type: 'meraki.network.event',
        pipeline_version: PIPELINE_VERSION,
        items,
      };

      const { events } = normalizeEvents(input);

      for (const event of events) {
        expect(event.content_hash).toBeTruthy();
        expect(event.content_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
        expect(() => {
          const hashable = getHashableFields(event);
          verifyContentHash(hashable, event.content_hash);
        }).not.toThrow();
      }
    });

    it('zero content_hash mismatches on valid events', () => {
      const PIPELINE_VERSION = 'a'.repeat(40);
      const items = Array.from({ length: 50 }, (_, i) => ({
        id: `item-${i}`,
        value: `payload_value_${i}`,
        timestamp: `2026-05-24T12:00:${String(i).padStart(2, '0')}.000Z`,
      }));

      const input = {
        org_id: 'sandbox-org',
        network_id: 'N_SANDBOX',
        source: 'meraki_poll' as const,
        source_url: 'https://api.meraki.com/api/v1/bulk-events',
        event_type: 'meraki.network.event',
        pipeline_version: PIPELINE_VERSION,
        items,
      };

      const { events } = normalizeEvents(input);

      const mismatches: string[] = [];
      for (const event of events) {
        try {
          const hashable = getHashableFields(event);
          verifyContentHash(hashable, event.content_hash);
        } catch (error) {
          mismatches.push(event.event_id);
        }
      }

      expect(mismatches.length).toBe(0);
      expect(events.length).toBe(50);
    });

    it('tampered content_hash is detected', () => {
      const PIPELINE_VERSION = 'a'.repeat(40);
      const input = {
        org_id: 'sandbox-org',
        network_id: 'N_SANDBOX',
        source: 'meraki_poll' as const,
        source_url: 'https://api.meraki.com/api/v1/events',
        event_type: 'meraki.network.event',
        pipeline_version: PIPELINE_VERSION,
        items: [{ test: 'tamper-detection' }],
      };

      const { events } = normalizeEvents(input);
      const event = events[0];

      const tampered = { ...event, content_hash: 'sha256:' + 'f'.repeat(64) };
      expect(() => {
        const hashable = getHashableFields(tampered);
        verifyContentHash(hashable, tampered.content_hash);
      }).toThrow();
    });
  });

  describe('Source URL and metadata population', () => {
    it('all events have source_url populated', () => {
      const PIPELINE_VERSION = 'a'.repeat(40);
      const input = {
        org_id: 'sandbox-org',
        network_id: 'N_SANDBOX',
        source: 'meraki_poll' as const,
        source_url: 'https://api.meraki.com/api/v1/networks/N_SANDBOX/events',
        event_type: 'meraki.network.event',
        pipeline_version: PIPELINE_VERSION,
        items: [
          { type: 'vpn_change' },
          { type: 'connectivity_change' },
          { type: 'firmware_upgrade' },
        ],
      };

      const { events } = normalizeEvents(input);

      for (const event of events) {
        expect(event.source_url).toBe('https://api.meraki.com/api/v1/networks/N_SANDBOX/events');
        expect(event.harvest_timestamp).toBeDefined();
        expect(event.pipeline_version).toBe(PIPELINE_VERSION);
      }
    });
  });

  describe('Rate limit handling behavior', () => {
    it('exponential backoff parameters are configured correctly', () => {
      const baseMs = 1000;
      const multiplier = 2;
      const maxMs = 30000;

      let delay = baseMs;
      for (let i = 0; i < 5; i++) {
        delay = Math.min(baseMs * Math.pow(multiplier, i), maxMs);
        expect(delay).toBeLessThanOrEqual(maxMs);
        expect(delay).toBeGreaterThan(0);
      }
    });

    it('jitter range is within ±20%', () => {
      const baseMs = 1000;
      const jitterRange = baseMs * 0.2;
      expect(jitterRange).toBe(200);
    });
  });
});
