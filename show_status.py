import sqlite3

conn = sqlite3.connect('data/honeypot.db')
c = conn.cursor()

print('='*60)
print('HONEYPOT DATABASE STATUS')
print('='*60)
print()

c.execute('SELECT COUNT(*) FROM attackers')
print(f'Attackers tracked: {c.fetchone()[0]}')

c.execute('SELECT COUNT(*) FROM connections')
print(f'Connections logged: {c.fetchone()[0]}')

print()
print('='*60)
print('LATEST ATTACKER')
print('='*60)

c.execute('SELECT ip_address, first_seen, last_seen, total_connections FROM attackers ORDER BY id DESC LIMIT 1')
row = c.fetchone()
if row:
    print(f'IP: {row[0]}')
    print(f'First seen: {row[1]}')
    print(f'Last seen: {row[2]}')
    print(f'Connections: {row[3]}')

print()
print('='*60)
print('LATEST CONNECTION')
print('='*60)

c.execute('SELECT ip_address, service_name, destination_port, timestamp FROM connections ORDER BY id DESC LIMIT 1')
row = c.fetchone()
if row:
    print(f'IP: {row[0]}')
    print(f'Service: {row[1]}')
    print(f'Port: {row[2]}')
    print(f'Timestamp: {row[3]}')

conn.close()
