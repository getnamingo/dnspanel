<?php

namespace App\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Container\ContainerInterface;
use League\ISO3166\ISO3166;
use PlexDNS\Service;
use PlexDNS\Exceptions\ProviderException;
use NetDNS2\Resolver as DNSResolver;

class ZonesController extends Controller
{
    public function listZones(Request $request, Response $response)
    {
        return view($response,'admin/zones/listZones.twig');
    }
   
    public function checkZone(Request $request, Response $response)
    {
        if ($request->getMethod() === 'POST') {
            // Retrieve POST data
            $data = $request->getParsedBody();
            $domainName = $data['domain_name'] ?? null;
            $token = $data['token'] ?? null;
            $claims = $data['claims'] ?? null;

            if ($domainName) {
                // Convert to Punycode if the domain is not in ASCII
                if (!mb_detect_encoding($domainName, 'ASCII', true)) {
                    $convertedDomain = idn_to_ascii($domainName, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);
                    if ($convertedDomain === false) {
                        $this->container->get('flash')->addMessage('error', 'Zone conversion to Punycode failed');
                        return $response->withHeader('Location', '/zone/check')->withStatus(302);
                    } else {
                        $domainName = $convertedDomain;
                    }
                }

                $invalid_domain = validate_label($domainName, $this->container->get('db'));
                if ($invalid_domain) {
                    $this->container->get('flash')->addMessage('error', 'Domain ' . $domainName . ' is not available: ' . $invalid_domain);
                    return $response->withHeader('Location', '/zone/check')->withStatus(302);
                }
                
                $resolver = new DNSResolver();

                try {
                    $nsResponse = $resolver->query($domainName, 'NS');
                } catch (Exception $e) {
                    $nsCheck = [
                        'healthy'    => false,
                        'error'      => "NS lookup failed: " . $e->getMessage(),
                        'soa_serial' => null
                    ];
                } catch (\NetDns2\Exception $e) {
                    $nsCheck = [
                        'healthy'    => false,
                        'error'      => "NS lookup failed: " . $e->getMessage(),
                        'soa_serial' => null
                    ];
                }

                if (empty($nsResponse->answer)) {
                    $nsCheck = [
                        'healthy'    => false,
                        'error'      => "No NS records found. Zone might not be properly delegated.",
                        'soa_serial' => null
                    ];
                }

                try {
                    $soaResponse = $resolver->query($domainName, 'SOA');
                } catch (Exception $e) {
                    $soaCheck = [
                        'healthy'    => false,
                        'error'      => "SOA lookup failed: " . $e->getMessage(),
                        'soa_serial' => null
                    ];
                }

                if (empty($soaResponse->answer)) {
                    $soaCheck = [
                        'healthy'    => false,
                        'error'      => "No SOA record found for zone.",
                        'soa_serial' => null
                    ];
                }

                // Assume the first SOA record is the primary one.
                $soaRecord  = $soaResponse->answer[0];
                $soaSerial  = $soaRecord->serial;

                // 3. (Optional) Verify that all NS servers return the same SOA serial.
                $issues = [];
                foreach ($nsResponse->answer as $nsRecord) {
                    // Clean the NS server name (remove trailing dot).
                    $nsServer = rtrim($nsRecord->nsdname, '.');

                    try {
                        $resolver = new DNSResolver();
                        $nsRecord = (object) ['nsdname' => $nsServer]; 

                        // Clean the NS name
                        $nsServer = rtrim($nsRecord->nsdname, '.');

                        // Resolve NS hostname to an IP address
                        $resolverTemp = new DNSResolver();
                        $nsIpResponse = $resolverTemp->query($nsServer, 'A'); // Get IPv4 address (use 'AAAA' for IPv6)

                        if (!empty($nsIpResponse->answer)) {
                            $nsIp = strval($nsIpResponse->answer[0]->address);
                        } else {
                            throw new Exception("Could not resolve nameserver IP.");
                        }

                        // Set resolver to query this specific nameserver.
                        $resolver->nameservers = [$nsIp];
                        $nsSoaResponse = $resolver->query($domainName, 'SOA');

                        if (empty($nsSoaResponse->answer)) {
                            $issues[] = "Nameserver {$nsServer} did not return an SOA record.";
                            continue;
                        }

                        $nsSoaSerial = $nsSoaResponse->answer[0]->serial;
                        if ($nsSoaSerial != $soaSerial) {
                            $issues[] = "Nameserver {$nsServer} returned differing SOA serial ({$nsSoaSerial} vs expected {$soaSerial}).";
                        }
                    } catch (Exception $e) {
                        $issues[] = "Error querying nameserver {$nsServer}: " . $e->getMessage();
                    }
                }

                $healthy = empty($issues);

                $result = [
                    'healthy'    => $healthy,
                    'error'      => $healthy ? null : implode(" ", $issues),
                    'soa_serial' => $soaSerial
                ];

                if ($healthy) {
                    $this->container->get('flash')->addMessage('success', "Zone is healthy. SOA Serial: $soaSerial");
                } else {
                    $this->container->get('flash')->addMessage('warning', "Zone issues found: " . implode(", ", $issues));
                }
                return $response->withHeader('Location', '/zone/check')->withStatus(302);
            }
        }

        // Default view for GET requests or if POST data is not set
        return view($response,'admin/zones/checkZone.twig');
    }
    
    public function createZone(Request $request, Response $response)
    {
        if ($request->getMethod() === 'POST') {
            // Retrieve POST data
            $data = $request->getParsedBody();
            $db = $this->container->get('db');
            $pdo = $this->container->get('pdo');
            
            $domainName = $data['domainName'] ?? null;
            // Convert to Punycode if the domain is not in ASCII
            if (!mb_detect_encoding($domainName, 'ASCII', true)) {
                $convertedDomain = idn_to_ascii($domainName, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);
                if ($convertedDomain === false) {
                    $this->container->get('flash')->addMessage('error', 'Domain conversion to Punycode failed');
                    return $response->withHeader('Location', '/zone/create')->withStatus(302);
                } else {
                    $domainName = $convertedDomain;
                }
            }

            $invalid_domain = validate_label($domainName, $db);

            if ($invalid_domain) {
                $this->container->get('flash')->addMessage('error', 'Error creating zone: Invalid zone name');
                return $response->withHeader('Location', '/zone/create')->withStatus(302);
            }

            $domain_already_exist = $db->selectValue(
                'SELECT id FROM zones WHERE domain_name = ? LIMIT 1',
                [$domainName]
            );

            if ($domain_already_exist) {
                $this->container->get('flash')->addMessage('error', 'Error creating zone: Zone name already exists');
                return $response->withHeader('Location', '/zone/create')->withStatus(302);
            }

            try {
                $provider = $data['provider'] ?? null;
                $providerDisplay = getProviderDisplayName($provider);

                if (!$provider) {
                    $this->container->get('flash')->addMessage('error', 'Error: Missing required environment variables in .env file (PROVIDER)');
                    return $response->withHeader('Location', '/zone/create')->withStatus(302);
                }

                $credentials = getProviderCredentials($provider);

                if (empty($credentials)) {
                    $this->container->get('flash')->addMessage('error', "Error: Missing required credentials for provider ($providerDisplay) in .env file.");
                    return $response->withHeader('Location', '/zone/create')->withStatus(302);
                }

                $apiKey = $credentials['API_KEY'] ?? null;
                $bindip = $credentials['BIND_IP'] ?? '127.0.0.1';
                $powerdnsip = $credentials['POWERDNS_IP'] ?? '127.0.0.1';
                $cloudnsAuthId = $credentials['AUTH_ID'] ?? null;
                $cloudnsAuthPassword = $credentials['AUTH_PASSWORD'] ?? null;

                if ($providerDisplay === 'ClouDNS' && (empty($cloudnsAuthId) || empty($cloudnsAuthPassword))) {
                    $this->container->get('flash')->addMessage('error', 'Error: Invalid ClouDNS credentials (AUTH_ID and AUTH_PASSWORD) in .env');
                    return $response->withHeader('Location', '/zone/create')->withStatus(302);
                }

                $config = [
                    'domain_name' => $domainName,
                    'provider' => $providerDisplay,
                    'apikey' => $apiKey,
                ];
                if ($bindip !== '127.0.0.1' && isValidIP($bindip)) {
                    $config['bindip'] = $bindip;
                }
                if ($powerdnsip !== '127.0.0.1' && isValidIP($powerdnsip)) {
                    $config['powerdnsip'] = $powerdnsip;
                }
                if ($providerDisplay === 'ClouDNS') {
                    $config['cloudns_auth_id'] = $cloudnsAuthId;
                    $config['cloudns_auth_password'] = $cloudnsAuthPassword;
                }

                $service = new Service($pdo);
                $domainOrder = [
                    'client_id' => $_SESSION['auth_user_id'],
                    'config' => json_encode($config),
                ];
                $domain = $service->createDomain($domainOrder);
            } catch (\RuntimeException $e) {
                $this->container->get('flash')->addMessage('error', $e->getMessage());
                return $response->withHeader('Location', '/zone/create')->withStatus(302);
            } catch (\Throwable $e) {
                $this->container->get('flash')->addMessage('error', 'Unexpected failure during zone create: ' . $e->getMessage());
                return $response->withHeader('Location', '/zone/create')->withStatus(302);
            }

            $crdate = $db->selectValue(
                "SELECT created_at FROM zones WHERE domain_name = ? LIMIT 1",
                [$domainName]
            );
            
            $this->container->get('flash')->addMessage('success', 'Zone ' . $domainName . ' has been created successfully on ' . $crdate);
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        $db = $this->container->get('db');
        $users = $db->select("SELECT id, email, username FROM users");
        $user = $_SESSION["auth_roles"] != 0 ? true : null;

        // Default view for GET requests or if POST data is not set
        return view($response,'admin/zones/createZone.twig', [
            'users' => $users,
            'user' => $user,
            'providers' => getActiveProviders()
        ]);
    }
    
    public function viewZone(Request $request, Response $response, $args) 
    {
        $db = $this->container->get('db');
        // Get the current URI
        $uri = $request->getUri()->getPath();

        if ($args) {
            $args = strtolower(trim($args));

            if (!preg_match('/^([a-z0-9]([-a-z0-9]*[a-z0-9])?\.)*[a-z0-9]([-a-z0-9]*[a-z0-9])?$/', $args)) {
                $this->container->get('flash')->addMessage('error', 'Invalid zone format');
                return $response->withHeader('Location', '/zones')->withStatus(302);
            }
        
            $domain = $db->selectRow('SELECT id, domain_name, client_id, created_at, updated_at, provider_id, zoneId FROM zones WHERE domain_name = ?',
            [ $args ]);

            if ($domain) {
                $records = $db->select(
                    'SELECT recordId, type, host, value, ttl, priority
                     FROM records
                     WHERE domain_id = ?
                     ORDER BY
                        CASE type
                            WHEN \'SOA\'   THEN 1
                            WHEN \'NS\'    THEN 2
                            WHEN \'A\'     THEN 3
                            WHEN \'AAAA\'  THEN 4
                            WHEN \'CNAME\' THEN 5
                            WHEN \'MX\'    THEN 6
                            WHEN \'TXT\'   THEN 7
                            WHEN \'SPF\'   THEN 8
                            WHEN \'SRV\'   THEN 9
                            ELSE 99
                        END,
                        host,
                        value',
                    [$domain['id']]
                );

                $users = $db->selectRow('SELECT id, email, username FROM users WHERE id = ?', [$domain['client_id']]);

                if (strpos($domain['domain_name'], 'xn--') === 0) {
                    $domain['domain_name_o'] = $domain['domain_name'];
                    $domain['domain_name'] = idn_to_utf8($domain['domain_name'], IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);
                } else {
                    $domain['domain_name_o'] = $domain['domain_name'];
                }

                return view($response,'admin/zones/viewZone.twig', [
                    'domain' => $domain,
                    'records' => $records,
                    'users' => $users,
                    'currentUri' => $uri
                ]);
            } else {
                // Domain does not exist, redirect to the zones view
                return $response->withHeader('Location', '/zones')->withStatus(302);
            }

        } else {
            // Redirect to the zones view
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

    }
    
    public function updateZone(Request $request, Response $response, $args)
    {
        $db = $this->container->get('db');
        if ($_SESSION["auth_roles"] != 0) {
            $registrar = true;
        } else {
            $registrar = null;
        }
        
        $uri = $request->getUri()->getPath();

        if ($args) {
            $args = strtolower(trim($args));

            if (!preg_match('/^([a-z0-9]([-a-z0-9]*[a-z0-9])?\.)*[a-z0-9]([-a-z0-9]*[a-z0-9])?$/', $args)) {
                $this->container->get('flash')->addMessage('error', 'Invalid zone format');
                return $response->withHeader('Location', '/zones')->withStatus(302);
            }

            $domain = $db->selectRow('SELECT id, domain_name, client_id, created_at, updated_at, provider_id, zoneId FROM zones WHERE domain_name = ?',
            [ $args ]);

            if ($domain) {
                $records = $db->select(
                    'SELECT recordId, type, host, value, ttl, priority
                     FROM records
                     WHERE domain_id = ?
                     ORDER BY
                        CASE type
                            WHEN \'SOA\'   THEN 1
                            WHEN \'NS\'    THEN 2
                            WHEN \'A\'     THEN 3
                            WHEN \'AAAA\'  THEN 4
                            WHEN \'CNAME\' THEN 5
                            WHEN \'MX\'    THEN 6
                            WHEN \'TXT\'   THEN 7
                            WHEN \'SPF\'   THEN 8
                            WHEN \'SRV\'   THEN 9
                            ELSE 99
                        END,
                        host,
                        value',
                    [$domain['id']]
                );

                $users = $db->selectRow('SELECT id, email, username FROM users WHERE id = ?', [$domain['client_id']]);

                if (strpos($domain['domain_name'], 'xn--') === 0) {
                    $domain['domain_name_o'] = $domain['domain_name'];
                    $domain['domain_name'] = idn_to_utf8($domain['domain_name'], IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);
                } else {
                    $domain['domain_name_o'] = $domain['domain_name'];
                }
                $_SESSION['domains_to_update'] = [$domain['domain_name_o']];
                
                return view($response,'admin/zones/updateZone.twig', [
                    'domain' => $domain,
                    'records' => $records,
                    'users' => $users,
                    'registrar' => $registrar,
                    'currentUri' => $uri,
               ]);
            } else {
                // Domain does not exist, redirect to the zones view
                return $response->withHeader('Location', '/zones')->withStatus(302);
            }

        } else {
            // Redirect to the zones view
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }
    }
    
    public function updateZoneProcess(Request $request, Response $response)
    {
        if ($request->getMethod() === 'POST') {
            // Retrieve POST data
            $data = $request->getParsedBody();
            $db = $this->container->get('db');
            $pdo = $this->container->get('pdo');
            
            if (!empty($_SESSION['domains_to_update'])) {
                $domainName = $_SESSION['domains_to_update'][0];
            } else {
                $this->container->get('flash')->addMessage('error', 'No zone specified for update');
                return $response->withHeader('Location', '/zones')->withStatus(302);
            }
            $domain_id = $db->selectValue('SELECT id FROM zones WHERE domain_name = ?', [$domainName]);

            $record_type = strtoupper($data['record_type'] ?? '');
            $record_name = $data['record_name']   ?? "";
            $record_value = trim((string)($data['record_value'] ?? ''));
            $record_ttl = $data['record_ttl'] ?? null;
            $record_priority = $data['record_priority'] ?? null;
            
            if ($record_type === '') {
                $this->container->get('flash')->addMessage('error', 'Record type is required');
                return $response->withHeader('Location', '/zone/create')->withStatus(302);
            }

            if ($record_value === '' && !in_array($record_type, ['NS', 'SOA'], true)) {
                $this->container->get('flash')->addMessage('error', 'Record value is required.');
                return $response->withHeader('Location', '/zone/create')->withStatus(302);
            }

            if ($record_ttl === null || !ctype_digit((string)$record_ttl) || (int)$record_ttl <= 0) {
                $this->container->get('flash')->addMessage('error', 'TTL must be a positive integer');
                return $response->withHeader('Location', '/zone/create')->withStatus(302);
            }
            $record_ttl = (int)$record_ttl;

            $record_priority = (
                in_array($record_type, ['MX', 'SRV'], true) &&
                ctype_digit((string)$record_priority)
            ) ? (int)$record_priority : 0;

            if ($record_name !== '') {
                if (!isHostname($record_name)) {
                    $this->container->get('flash')->addMessage('error', 'Invalid record name. Use only valid DNS labels (letters, digits, hyphens, dots) or IDN');
                    return $response->withHeader('Location', '/zone/create')->withStatus(302);
                }
            }

            switch ($record_type) {
                case 'A':
                    if (!filter_var($record_value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $this->container->get('flash')->addMessage('error', 'Invalid IPv4 address for A record');
                        return $response->withHeader('Location', '/zone/create')->withStatus(302);
                    }
                    break;

                case 'AAAA':
                    if (!filter_var($record_value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                        $this->container->get('flash')->addMessage('error', 'Invalid IPv6 address for AAAA record');
                        return $response->withHeader('Location', '/zone/create')->withStatus(302);
                    }
                    break;

                case 'TXT':
                case 'SPF':
                    // Auto-wrap in quotes if not already quoted
                    if (!(str_starts_with($record_value, '"') && str_ends_with($record_value, '"'))) {
                        $record_value = '"' . $record_value . '"';
                    }
                    break;

                default:
                    // For other types just ensure no control chars
                    if (preg_match('/[\x00-\x1F]/', $record_value)) {
                        $this->container->get('flash')->addMessage('error', 'Record value contains invalid control characters');
                        return $response->withHeader('Location', '/zone/create')->withStatus(302);
                    }
                    break;
            }

            try {
                $configJson = $db->selectValue('SELECT config FROM zones WHERE domain_name = ?', [$domainName]);
                $configArray = json_decode($configJson, true);
                $provider = strtoupper($configArray['provider']) ?? null;
                $providerDisplay = getProviderDisplayName($provider);

                if (!$provider) {
                    $this->container->get('flash')->addMessage('error', 'Error: Missing required environment variables in .env file (PROVIDER)');
                    return $response->withHeader('Location', '/zone/create')->withStatus(302);
                }

                $credentials = getProviderCredentials($provider);

                if (empty($credentials)) {
                    $this->container->get('flash')->addMessage('error', "Error: Missing required credentials for provider ($providerDisplay) in .env file.");
                    return $response->withHeader('Location', '/zone/create')->withStatus(302);
                }

                $apiKey = $credentials['API_KEY'] ?? null;
                $bindip = $credentials['BIND_IP'] ?? '127.0.0.1';
                $powerdnsip = $credentials['POWERDNS_IP'] ?? '127.0.0.1';
                $cloudnsAuthId = $credentials['AUTH_ID'] ?? null;
                $cloudnsAuthPassword = $credentials['AUTH_PASSWORD'] ?? null;

                if ($providerDisplay === 'ClouDNS' && (empty($cloudnsAuthId) || empty($cloudnsAuthPassword))) {
                    $this->container->get('flash')->addMessage('error', 'Error: Invalid ClouDNS credentials (AUTH_ID and AUTH_PASSWORD) in .env');
                    return $response->withHeader('Location', '/zone/create')->withStatus(302);
                }

                $service = new Service($pdo);
                $recordData = [
                    'domain_name' => $domainName,
                    'record_name' => $record_name,
                    'record_type' => $record_type,
                    'record_value' => $record_value,
                    'record_ttl' => $record_ttl,
                    'record_priority' => $record_priority,
                    'provider' => $providerDisplay,
                    'apikey' => $apiKey
                ];
                if ($providerDisplay === 'Desec' && $record_ttl < 3600) {
                    $recordData['record_ttl'] = 3600;
                }
                if (
                    $providerDisplay === 'Desec' &&
                    in_array($record_type, ['MX', 'CNAME'], true)
                ) {
                    if (!str_ends_with($record_value, '.')) {
                        $record_value .= '.'; // add trailing dot
                        $recordData['record_value'] = $record_value;
                    }
                }
                if ($bindip !== '127.0.0.1' && isValidIP($bindip)) {
                    $recordData['bindip'] = $bindip;
                }
                if ($powerdnsip !== '127.0.0.1' && isValidIP($powerdnsip)) {
                    $recordData['powerdnsip'] = $powerdnsip;
                }
                if ($providerDisplay === 'ClouDNS') {
                    $recordData['cloudns_auth_id'] = $cloudnsAuthId;
                    $recordData['cloudns_auth_password'] = $cloudnsAuthPassword;
                }
                $recordId = $service->addRecord($recordData);
            } catch (\RuntimeException  $e) {
                $this->container->get('flash')->addMessage('error', $e->getMessage());
                return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
            } catch (\Throwable  $e) {
                $this->container->get('flash')->addMessage('error', 'Unexpected failure during creation: ' . $e->getMessage());
                return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
            }

            $currentDateTime = new \DateTime();
            $update = $currentDateTime->format('Y-m-d H:i:s.v'); // Current timestamp

            unset($_SESSION['domains_to_update']);
            $this->container->get('flash')->addMessage('success', 'Record with value ' . $record_value . ' has been created successfully on ' . $update);
            return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
        }
    }
    
    public function zoneUpdateRecord(Request $request, Response $response)
    {
        $db = $this->container->get('db');
        $pdo = $this->container->get('pdo');
        $data = $request->getParsedBody();
        $uri = $request->getUri()->getPath();

        if (!empty($_SESSION['domains_to_update'])) {
            $domainName = $_SESSION['domains_to_update'][0];
        } else {
            $this->container->get('flash')->addMessage('error', 'No zone specified for update');
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        $record_type   = strtoupper($data['record_type'] ?? '');
        $record_name   = $data['record_name']   ?? "";
        $record_value  = trim((string)($data['record_value'] ?? ''));
        $record_ttl    = $data['record_ttl']    ?? null;
        $record_priority = $data['record_priority'] ?? null;

        if ($record_type === '') {
            $this->container->get('flash')->addMessage('error', 'Record type is required');
            return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
        }

        if ($record_value === '' && !in_array($record_type, ['NS', 'SOA'], true)) {
            $this->container->get('flash')->addMessage('error', 'Record value is required.');
            return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
        }

        if ($record_ttl === null || !ctype_digit((string)$record_ttl) || (int)$record_ttl <= 0) {
            $this->container->get('flash')->addMessage('error', 'TTL must be a positive integer');
            return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
        }
        $record_ttl = (int)$record_ttl;

        $record_priority = (
            in_array($record_type, ['MX', 'SRV'], true) &&
            ctype_digit((string)$record_priority)
        ) ? (int)$record_priority : 0;

        if ($record_name !== '') {
            if (!isHostname($record_name)) {
                $this->container->get('flash')->addMessage('error', 'Invalid record name. Use only valid DNS labels (letters, digits, hyphens, dots) or IDN');
                return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
            }
        }

        switch ($record_type) {
            case 'A':
                if (!filter_var($record_value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $this->container->get('flash')->addMessage('error', 'Invalid IPv4 address for A record');
                    return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
                }
                break;

            case 'AAAA':
                if (!filter_var($record_value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $this->container->get('flash')->addMessage('error', 'Invalid IPv6 address for AAAA record');
                    return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
                }
                break;

            case 'TXT':
            case 'SPF':
                // Auto-wrap in quotes if not already quoted
                if (!(str_starts_with($record_value, '"') && str_ends_with($record_value, '"'))) {
                    $record_value = '"' . $record_value . '"';
                }
                break;

            default:
                // For other types just ensure no control chars
                if (preg_match('/[\x00-\x1F]/', $record_value)) {
                    $this->container->get('flash')->addMessage('error', 'Record value contains invalid control characters');
                    return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
                }
                break;
        }

        $zone_id = $db->selectValue('SELECT id FROM zones WHERE domain_name = ? LIMIT 1', [$domainName]);

        $oldValue = $data['old_value'] ?? null;

        $recordRow = $db->selectRow(
            'SELECT recordId, priority 
             FROM records 
             WHERE domain_id = ? 
               AND type = ? 
               AND host = ? 
               AND value = ?
             LIMIT 1',
            [$zone_id, $record_type, $record_name, $oldValue]
        );

        if (!$recordRow) {
            $this->container->get('flash')->addMessage('error', 'Record not found for update');
            return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
        }

        $record_id = $recordRow['recordId'];

        try {
            $configJson = $db->selectValue('SELECT config FROM zones WHERE domain_name = ?', [$domainName]);
            $configArray = json_decode($configJson, true);
            $provider = strtoupper($configArray['provider']) ?? null;
            $providerDisplay = getProviderDisplayName($provider);

            if (!$provider) {
                $this->container->get('flash')->addMessage('error', 'Error: Missing required environment variables in .env file (PROVIDER)');
                return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
            }

            $credentials = getProviderCredentials($provider);

            if (empty($credentials)) {
                $this->container->get('flash')->addMessage('error', "Error: Missing required credentials for provider ($providerDisplay) in .env file.");
                return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
            }

            $apiKey = $credentials['API_KEY'] ?? null;
            $bindip = $credentials['BIND_IP'] ?? '127.0.0.1';
            $powerdnsip = $credentials['POWERDNS_IP'] ?? '127.0.0.1';
            $cloudnsAuthId = $credentials['AUTH_ID'] ?? null;
            $cloudnsAuthPassword = $credentials['AUTH_PASSWORD'] ?? null;

            if ($providerDisplay === 'ClouDNS' && (empty($cloudnsAuthId) || empty($cloudnsAuthPassword))) {
                $this->container->get('flash')->addMessage('error', 'Error: Invalid ClouDNS credentials (AUTH_ID and AUTH_PASSWORD) in .env');
                return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
            }

            $currentDateTime = new \DateTime();
            $update = $currentDateTime->format('Y-m-d H:i:s.v');

            $service = new Service($pdo);
            if ($data['action'] == 'delete') {
                $deleteData = [
                    'domain_name' => $domainName,
                    'record_id' => $record_id,
                    'record_name' => $record_name,
                    'record_type' => $record_type,
                    'record_value' => $record_value,
                    'old_value' => $oldValue,
                    'provider' => $providerDisplay,
                    'apikey' => $apiKey
                ];
                if ($bindip !== '127.0.0.1' && isValidIP($bindip)) {
                    $deleteData['bindip'] = $bindip;
                }
                if ($powerdnsip !== '127.0.0.1' && isValidIP($powerdnsip)) {
                    $deleteData['powerdnsip'] = $powerdnsip;
                }
                if ($providerDisplay === 'ClouDNS') {
                    $deleteData['cloudns_auth_id'] = $cloudnsAuthId;
                    $deleteData['cloudns_auth_password'] = $cloudnsAuthPassword;
                }
                $service->delRecord($deleteData);
                unset($_SESSION['domains_to_update']);
                unset($_SESSION['record_id']);
                $this->container->get('flash')->addMessage('error', 'Record has been deleted successfully on ' . $update);
                return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
            } else {
                $updateData = [
                    'domain_name' => $domainName,
                    'record_id' => $record_id,
                    'record_name' => $record_name,
                    'record_type' => $record_type,
                    'record_value' => $record_value,
                    'old_value' => $oldValue,
                    'record_ttl' => $record_ttl,
                    'record_priority' => $record_priority,
                    'provider' => $providerDisplay,
                    'apikey' => $apiKey
                ];
                if ($providerDisplay === 'Desec' && $record_ttl < 3600) {
                    $updateData['record_ttl'] = 3600;
                }
                if ($bindip !== '127.0.0.1' && isValidIP($bindip)) {
                    $updateData['bindip'] = $bindip;
                }
                if ($powerdnsip !== '127.0.0.1' && isValidIP($powerdnsip)) {
                    $updateData['powerdnsip'] = $powerdnsip;
                }
                if ($providerDisplay === 'ClouDNS') {
                    $updateData['cloudns_auth_id'] = $cloudnsAuthId;
                    $updateData['cloudns_auth_password'] = $cloudnsAuthPassword;
                }
                $service->updateRecord($updateData);
                unset($_SESSION['domains_to_update']);
                unset($_SESSION['record_id']);
                $this->container->get('flash')->addMessage('success', 'Record has been updated successfully on ' . $update);
                return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
            }
        } catch (\RuntimeException $e) {
            $this->container->get('flash')->addMessage('error', $e->getMessage());
            return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
        } catch (\Throwable $e) {
            $this->container->get('flash')->addMessage('error', 'Unexpected failure during update: ' . $e->getMessage());
            return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
        }
    }

    public function deleteZone(Request $request, Response $response, $args)
    {
        $db = $this->container->get('db');
        $pdo = $this->container->get('pdo');

        // Get the current URI
        $uri = $request->getUri()->getPath();

        if ($args) {
            $args = strtolower(trim($args));

            if (!preg_match('/^([a-z0-9]([-a-z0-9]*[a-z0-9])?\.)*[a-z0-9]([-a-z0-9]*[a-z0-9])?$/', $args)) {
                $this->container->get('flash')->addMessage('error', 'Invalid zone format');
                return $response->withHeader('Location', '/zones')->withStatus(302);
            }

            $configJson = $db->selectValue('SELECT config FROM zones WHERE domain_name = ?', [$args]);
            $configArray = json_decode($configJson, true);
            $provider = strtoupper($configArray['provider']) ?? null;
            $providerDisplay = getProviderDisplayName($provider);

            if (!$provider) {
                $this->container->get('flash')->addMessage('error', 'Error: Missing required environment variables in .env file (PROVIDER)');
                return $response->withHeader('Location', '/zones')->withStatus(302);
            }

            $credentials = getProviderCredentials($provider);

            if (empty($credentials)) {
                $this->container->get('flash')->addMessage('error', "Error: Missing required credentials for provider ($providerDisplay) in .env file.");
                return $response->withHeader('Location', '/zones')->withStatus(302);
            }

            $apiKey = $credentials['API_KEY'] ?? null;
            $bindip = $credentials['BIND_IP'] ?? '127.0.0.1';
            $powerdnsip = $credentials['POWERDNS_IP'] ?? '127.0.0.1';
            $cloudnsAuthId = $credentials['AUTH_ID'] ?? null;
            $cloudnsAuthPassword = $credentials['AUTH_PASSWORD'] ?? null;

            if ($providerDisplay === 'ClouDNS' && (empty($cloudnsAuthId) || empty($cloudnsAuthPassword))) {
                $this->container->get('flash')->addMessage('error', 'Error: Invalid ClouDNS credentials (AUTH_ID and AUTH_PASSWORD) in .env');
                return $response->withHeader('Location', '/zones')->withStatus(302);
            }

            $config = [
                'domain_name' => $args,
                'provider' => $providerDisplay,
                'apikey' => $apiKey,
            ];
            if ($bindip !== '127.0.0.1' && isValidIP($bindip)) {
                $config['bindip'] = $bindip;
            }
            if ($powerdnsip !== '127.0.0.1' && isValidIP($powerdnsip)) {
                $config['powerdnsip'] = $powerdnsip;
            }
            if ($providerDisplay === 'ClouDNS') {
                $config['cloudns_auth_id'] = $cloudnsAuthId;
                $config['cloudns_auth_password'] = $cloudnsAuthPassword;
            }

            $service = new Service($pdo);
            $domainOrder = [
                'config' => json_encode($config),
            ];
            $service->deleteDomain($domainOrder);

            $this->container->get('flash')->addMessage('success', 'Zone ' . $args . ' deleted successfully');
            return $response->withHeader('Location', '/zones')->withStatus(302);
        } else {
            // Redirect to the domains view
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }
    }

}