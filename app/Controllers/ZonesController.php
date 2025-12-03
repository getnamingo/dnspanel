<?php

namespace App\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Container\ContainerInterface;
use League\ISO3166\ISO3166;
use PlexDNS\Service;
use PlexDNS\Exceptions\ProviderException;
use NetDNS2\Resolver as DNSResolver;
use Utopia\DNS\Client;
use Utopia\DNS\Message;
use Utopia\DNS\Message\Question;
use Utopia\DNS\Message\Record;

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
        if ($_SESSION["auth_roles"] != 0) {
            return $response->withHeader('Location', '/dashboard')->withStatus(302);
        }

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
                $currentDateTime = new \DateTime();
                $logdate = $currentDateTime->format('Y-m-d H:i:s.v');
                $db->insert(
                    'error_log',
                    [
                        'channel' => 'domain_manager',
                        'level' => 400,
                        'level_name' => 'ERROR',
                        'message' => "Unexpected failure during zone creation: " . $e->getMessage(),
                        'context' => json_encode([
                            'user_id' => $_SESSION['auth_user_id'] ?? null, 
                            'domain' => $domainName ?? null, 
                            'provider' => $providerDisplay ?? null,
                            'exception'    => [
                                'class'   => get_class($e),
                                'file'    => $e->getFile(),
                                'line'    => $e->getLine(),
                            ]
                        ]),
                        'extra'       => json_encode([
                            'trace' => $e->getTraceAsString(),
                        ]),
                        'created_at' => $logdate
                    ]
                );
                $this->container->get('flash')->addMessage('error', 'Zone creation failed. Please try again later');
                return $response->withHeader('Location', '/zone/create')->withStatus(302);
            } catch (\Throwable $e) {
                $currentDateTime = new \DateTime();
                $logdate = $currentDateTime->format('Y-m-d H:i:s.v');
                $db->insert(
                    'error_log',
                    [
                        'channel' => 'domain_manager',
                        'level' => 400,
                        'level_name' => 'ERROR',
                        'message' => "Unexpected failure during zone creation: " . $e->getMessage(),
                        'context' => json_encode([
                            'user_id' => $_SESSION['auth_user_id'] ?? null, 
                            'domain' => $domainName ?? null, 
                            'provider' => $providerDisplay ?? null,
                            'exception'    => [
                                'class'   => get_class($e),
                                'file'    => $e->getFile(),
                                'line'    => $e->getLine(),
                            ]
                        ]),
                        'extra'       => json_encode([
                            'trace' => $e->getTraceAsString(),
                        ]),
                        'created_at' => $logdate
                    ]
                );
                $this->container->get('flash')->addMessage('error', 'Zone creation failed. Please try again later');
                return $response->withHeader('Location', '/zone/create')->withStatus(302);
            }

            $crdate = $db->selectValue(
                "SELECT created_at FROM zones WHERE domain_name = ? LIMIT 1",
                [$domainName]
            );

            if ($providerDisplay === 'Desec') {
                $db->update(
                    'zones',
                    ['provider_id' => 2],
                    ['domain_name' => $domainName]
                );
            } else {
                $dnssecSupportedProviders = ['ClouDNS', 'PowerDNS'];

                if (in_array($providerDisplay, $dnssecSupportedProviders, true)) {
                    $db->update(
                        'zones',
                        ['provider_id' => 1],
                        ['domain_name' => $domainName]
                    );
                }
            }

            $this->container->get('flash')->addMessage('success', 'Zone ' . $domainName . ' has been created successfully on ' . $crdate);
            return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
        }

        // Default view for GET requests or if POST data is not set
        return view($response,'admin/zones/createZone.twig', [
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

    public function zoneDetails(Request $request, Response $response, $args) 
    {
        $db = $this->container->get('db');
        $uri = $request->getUri()->getPath();

        if (!$args) {
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        $zone = strtolower(trim($args));

        if (!preg_match('/^([a-z0-9]([-a-z0-9]*[a-z0-9])?\.)*[a-z0-9]([-a-z0-9]*[a-z0-9])?$/', $zone)) {
            $this->container->get('flash')->addMessage('error', 'Invalid zone format');
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        $domain = $db->selectRow('SELECT id, domain_name, client_id, created_at, updated_at, provider_id, zoneId, config FROM zones WHERE domain_name = ?',
        [ $zone ]);
        
        if (!$domain) {
            $this->container->get('flash')->addMessage('error', 'Zone not found');
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }
        
        $resolverAddress = envi('DNS_RESOLVER') ?? '1.1.1.1';
        $config = json_decode($domain['config'], true);
        $provider = $config['provider'] ?? null;

        $client = new Client($resolverAddress);

        $types = [
            Record::TYPE_A,
            Record::TYPE_AAAA,
            Record::TYPE_CNAME,
            Record::TYPE_MX,
            Record::TYPE_TXT,
            Record::TYPE_NS,
            Record::TYPE_SOA,
            Record::TYPE_SRV,
            Record::TYPE_CAA,
        ];

        $recordsByType = [];
        $lookupErrors  = [];
        
        $typeNames = [
            Record::TYPE_A     => 'A',
            Record::TYPE_AAAA  => 'AAAA',
            Record::TYPE_CNAME => 'CNAME',
            Record::TYPE_MX    => 'MX',
            Record::TYPE_TXT   => 'TXT',
            Record::TYPE_NS    => 'NS',
            Record::TYPE_SOA   => 'SOA',
            Record::TYPE_SRV   => 'SRV',
            Record::TYPE_CAA   => 'CAA',
        ];

        foreach ($types as $type) {
            try {
                $query = Message::query(
                    new Question($domain['domain_name'], $type)
                );

                $dnsResponse = $client->query($query);

                foreach ($dnsResponse->answers as $answer) {
                    $typeName = $typeNames[$answer->type] ?? (string) $answer->type;

                    $recordsByType[$typeName][] = [
                        'name'  => rtrim($answer->name, '.'),
                        'ttl'   => $answer->ttl,
                        'type'  => $typeName,
                        'value' => (string) $answer->rdata,
                    ];
                }
            } catch (\Throwable $e) {
                $typeName = $typeNames[$type] ?? (string) $type;
                $lookupErrors[] = sprintf('%s lookup failed: %s', $typeName, $e->getMessage());
            }
        }

        if (!empty($lookupErrors)) {
            $this->container->get('flash')->addMessage(
                'error',
                'Unable to load DNS records for this zone (resolver error). Please try again later.'
            );
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        return view($response, 'admin/zones/zoneDetails.twig', [
            'domain'         => $domain,
            'recordsByType'  => $recordsByType,
            'resolver'       => $resolverAddress,
            'currentUri'     => $uri,
            'provider'       => $provider,
        ]);
    }

    public function zoneDNSSEC(Request $request, Response $response, $args) 
    {
        $db = $this->container->get('db');
        $uri = $request->getUri()->getPath();
        $pdo = $this->container->get('pdo');

        if (!$args) {
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        $zone = strtolower(trim($args));

        if (!preg_match('/^([a-z0-9]([-a-z0-9]*[a-z0-9])?\.)*[a-z0-9]([-a-z0-9]*[a-z0-9])?$/', $zone)) {
            $this->container->get('flash')->addMessage('error', 'Invalid zone format');
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        $domain = $db->selectRow('SELECT id, domain_name, client_id, created_at, updated_at, provider_id, zoneId, config FROM zones WHERE domain_name = ?',
        [ $zone ]);
        
        if (!$domain) {
            $this->container->get('flash')->addMessage('error', 'Zone not found');
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        // Map provider_id to DNSSEC status: 0 = not supported, 1 = supported (disabled), 2 = enabled
        $dnssecStatus = isset($domain['provider_id']) ? (int)$domain['provider_id'] : 0;
        $domain['dnssec_status'] = $dnssecStatus;

        if ($dnssecStatus === 1) {
            try {
                $configJson = $db->selectValue('SELECT config FROM zones WHERE domain_name = ?', [$zone]);
                $configArray = json_decode($configJson, true);
                $provider = strtoupper($configArray['provider']) ?? null;
                $providerDisplay = getProviderDisplayName($provider);

                if (!$provider) {
                    $this->container->get('flash')->addMessage('error', 'Error: Missing required environment variables in .env file (PROVIDER)');
                    return $response->withHeader('Location', '/zone/update/'.$zone)->withStatus(302);
                }

                $credentials = getProviderCredentials($provider);

                if (empty($credentials)) {
                    $this->container->get('flash')->addMessage('error', "Error: Missing required credentials for provider ($providerDisplay) in .env file.");
                    return $response->withHeader('Location', '/zone/update/'.$zone)->withStatus(302);
                }

                $apiKey = $credentials['API_KEY'] ?? null;
                $bindip = $credentials['BIND_IP'] ?? '127.0.0.1';
                $powerdnsip = $credentials['POWERDNS_IP'] ?? '127.0.0.1';
                $cloudnsAuthId = $credentials['AUTH_ID'] ?? null;
                $cloudnsAuthPassword = $credentials['AUTH_PASSWORD'] ?? null;

                if ($providerDisplay === 'ClouDNS' && (empty($cloudnsAuthId) || empty($cloudnsAuthPassword))) {
                    $this->container->get('flash')->addMessage('error', 'Error: Invalid ClouDNS credentials (AUTH_ID and AUTH_PASSWORD) in .env');
                    return $response->withHeader('Location', '/zone/update/'.$zone)->withStatus(302);
                }
                    
                $service = new Service($pdo);
                $recordData = [
                    'domain_name' => $args,
                    'provider' => $providerDisplay,
                    'apikey' => $apiKey
                ];
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
                $ds = $service->enableDNSSEC($recordData);

                $db->update(
                    'zones',
                    [
                        'provider_id' => 2
                    ],
                    [
                        'domain_name' => $zone
                    ]
                );
            } catch (\RuntimeException  $e) {
                $currentDateTime = new \DateTime();
                $logdate = $currentDateTime->format('Y-m-d H:i:s.v');
                $db->insert(
                    'error_log',
                    [
                        'channel' => 'domain_manager',
                        'level' => 400,
                        'level_name' => 'ERROR',
                        'message' => "Unexpected failure during DNSSEC enable: " . $e->getMessage(),
                        'context' => json_encode([
                           'user_id' => $_SESSION['auth_user_id'] ?? null, 
                            'domain' => $zone ?? null, 
                            'provider' => $providerDisplay ?? null,
                            'exception'    => [
                                'class'   => get_class($e),
                                'file'    => $e->getFile(),
                                'line'    => $e->getLine(),
                            ]
                        ]),
                        'extra'       => json_encode([
                            'trace' => $e->getTraceAsString(),
                        ]),
                        'created_at' => $logdate
                    ]
                );
                $this->container->get('flash')->addMessage('error', 'DNSSEC enable failed. Please try again later');
                return $response->withHeader('Location', '/zone/update/'.$zone)->withStatus(302);
            } catch (\Throwable  $e) {
                $currentDateTime = new \DateTime();
                $logdate = $currentDateTime->format('Y-m-d H:i:s.v');
                $db->insert(
                    'error_log',
                    [
                        'channel' => 'domain_manager',
                        'level' => 400,
                        'level_name' => 'ERROR',
                        'message' => "Unexpected failure during DNSSEC enable: " . $e->getMessage(),
                        'context' => json_encode([
                           'user_id' => $_SESSION['auth_user_id'] ?? null, 
                            'domain' => $zone ?? null, 
                            'provider' => $providerDisplay ?? null,
                            'exception'    => [
                                'class'   => get_class($e),
                                'file'    => $e->getFile(),
                                'line'    => $e->getLine(),
                            ]
                        ]),
                        'extra'       => json_encode([
                            'trace' => $e->getTraceAsString(),
                        ]),
                        'created_at' => $logdate
                    ]
                );
                $this->container->get('flash')->addMessage('error', 'DNSSEC enable failed. Please try again later');
                return $response->withHeader('Location', '/zone/update/'.$zone)->withStatus(302);
            }
        } else {
            return $response->withHeader('Location', '/zone/update/'.$zone)->withStatus(302);
        }

        return $response->withHeader('Location', '/zone/update/'.$zone)->withStatus(302);
    }

    public function updateZone(Request $request, Response $response, $args)
    {
        $db = $this->container->get('db');
        $pdo = $this->container->get('pdo');

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
                
                // Map provider_id to DNSSEC status: 0 = not supported, 1 = supported (disabled), 2 = enabled
                $dnssecStatus = isset($domain['provider_id']) ? (int)$domain['provider_id'] : 0;
                $domain['dnssec_status'] = $dnssecStatus;

                $dsList = [];
                if ($dnssecStatus === 2) {
                    try {
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
                    
                        $service = new Service($pdo);
                        $recordData = [
                            'domain_name' => $args,
                            'provider' => $providerDisplay,
                            'apikey' => $apiKey
                        ];
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
                        $dsOnly = $service->getDSRecords($recordData);
                        $dsOnly = $dsOnly ?? [];

                        $dsList = [];

                        foreach ($dsOnly as $ds) {
                            $parts = explode(' ', $ds, 4);

                            if (count($parts) === 4) {
                                $dsList[] = [
                                    'keytag'      => $parts[0],
                                    'algorithm'   => $parts[1],
                                    'digest_type' => $parts[2],
                                    'digest'      => $parts[3],
                                    'full'        => $ds,
                                ];
                            }
                        }
                    } catch (\RuntimeException  $e) {
                        $currentDateTime = new \DateTime();
                        $logdate = $currentDateTime->format('Y-m-d H:i:s.v');
                        $db->insert(
                            'error_log',
                            [
                                'channel' => 'domain_manager',
                                'level' => 400,
                                'level_name' => 'ERROR',
                                'message' => "Unexpected failure during DS retrieval: " . $e->getMessage(),
                                'context' => json_encode([
                                    'user_id' => $_SESSION['auth_user_id'] ?? null, 
                                    'domain' => $args ?? null, 
                                    'provider' => $providerDisplay ?? null,
                                    'exception'    => [
                                        'class'   => get_class($e),
                                        'file'    => $e->getFile(),
                                        'line'    => $e->getLine(),
                                    ]
                                ]),
                                'extra'       => json_encode([
                                    'trace' => $e->getTraceAsString(),
                                ]),
                                'created_at' => $logdate
                            ]
                        );
                        $this->container->get('flash')->addMessage('error', 'DS retrieval failed. Please try again later');
                        return $response->withHeader('Location', '/zones')->withStatus(302);
                    } catch (\Throwable  $e) {
                        $currentDateTime = new \DateTime();
                        $logdate = $currentDateTime->format('Y-m-d H:i:s.v');
                        $db->insert(
                            'error_log',
                            [
                                'channel' => 'domain_manager',
                                'level' => 400,
                                'level_name' => 'ERROR',
                                'message' => "Unexpected failure during DS retrieval: " . $e->getMessage(),
                                'context' => json_encode([
                                    'user_id' => $_SESSION['auth_user_id'] ?? null, 
                                    'domain' => $args ?? null, 
                                    'provider' => $providerDisplay ?? null,
                                    'exception'    => [
                                        'class'   => get_class($e),
                                        'file'    => $e->getFile(),
                                        'line'    => $e->getLine(),
                                    ]
                                ]),
                                'extra'       => json_encode([
                                    'trace' => $e->getTraceAsString(),
                                ]),
                                'created_at' => $logdate
                            ]
                        );
                        $this->container->get('flash')->addMessage('error', 'DS retrieval failed. Please try again later');
                        return $response->withHeader('Location', '/zones')->withStatus(302);
                    }
                }

                return view($response,'admin/zones/updateZone.twig', [
                    'domain' => $domain,
                    'records' => $records,
                    'users' => $users,
                    'registrar' => $registrar,
                    'currentUri' => $uri,
                    'dsList'    => $dsList
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
                $currentDateTime = new \DateTime();
                $logdate = $currentDateTime->format('Y-m-d H:i:s.v');
                $db->insert(
                    'error_log',
                    [
                        'channel' => 'domain_manager',
                        'level' => 400,
                        'level_name' => 'ERROR',
                        'message' => "Unexpected failure during record creation: " . $e->getMessage(),
                        'context' => json_encode([
                            'user_id' => $_SESSION['auth_user_id'] ?? null, 
                            'domain' => $domainName ?? null, 
                            'provider' => $providerDisplay ?? null,
                            'exception'    => [
                                'class'   => get_class($e),
                                'file'    => $e->getFile(),
                                'line'    => $e->getLine(),
                            ]
                        ]),
                        'extra'       => json_encode([
                            'trace' => $e->getTraceAsString(),
                        ]),
                        'created_at' => $logdate
                    ]
                );
                $this->container->get('flash')->addMessage('error', 'Record creation failed. Please try again later');
                return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
            } catch (\Throwable  $e) {
                $currentDateTime = new \DateTime();
                $logdate = $currentDateTime->format('Y-m-d H:i:s.v');
                $db->insert(
                    'error_log',
                    [
                        'channel' => 'domain_manager',
                        'level' => 400,
                        'level_name' => 'ERROR',
                        'message' => "Unexpected failure during record creation: " . $e->getMessage(),
                        'context' => json_encode([
                            'user_id' => $_SESSION['auth_user_id'] ?? null, 
                            'domain' => $domainName ?? null, 
                            'provider' => $providerDisplay ?? null,
                            'exception'    => [
                                'class'   => get_class($e),
                                'file'    => $e->getFile(),
                                'line'    => $e->getLine(),
                            ]
                        ]),
                        'extra'       => json_encode([
                            'trace' => $e->getTraceAsString(),
                        ]),
                        'created_at' => $logdate
                    ]
                );
                $this->container->get('flash')->addMessage('error', 'Record creation failed. Please try again later');
                return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
            }

            $currentDateTime = new \DateTime();
            $update = $currentDateTime->format('Y-m-d H:i:s.v');

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
            $currentDateTime = new \DateTime();
            $logdate = $currentDateTime->format('Y-m-d H:i:s.v');
            $db->insert(
                'error_log',
                [
                    'channel' => 'domain_manager',
                    'level' => 400,
                    'level_name' => 'ERROR',
                    'message' => "Unexpected failure during record " . $data['action'] . ": " . $e->getMessage(),
                    'context' => json_encode([
                        'user_id' => $_SESSION['auth_user_id'] ?? null, 
                        'domain' => $domainName ?? null, 
                        'provider' => $providerDisplay ?? null,
                        'exception'    => [
                        'class'   => get_class($e),
                        'file'    => $e->getFile(),
                        'line'    => $e->getLine(),
                    ]
                    ]),
                    'extra'       => json_encode([
                        'trace' => $e->getTraceAsString(),
                    ]),
                    'created_at' => $logdate
                ]
            );
            $this->container->get('flash')->addMessage('error', 'Zone record ' . $data['action'] . ' failed. Please try again later');
            return $response->withHeader('Location', '/zone/update/'.$domainName)->withStatus(302);
        } catch (\Throwable $e) {
            $currentDateTime = new \DateTime();
            $logdate = $currentDateTime->format('Y-m-d H:i:s.v');
            $db->insert(
                'error_log',
                [
                    'channel' => 'domain_manager',
                    'level' => 400,
                    'level_name' => 'ERROR',
                    'message' => "Unexpected failure during record " . $data['action'] . ": " . $e->getMessage(),
                    'context' => json_encode([
                        'user_id' => $_SESSION['auth_user_id'] ?? null, 
                        'domain' => $domainName ?? null, 
                        'provider' => $providerDisplay ?? null,
                        'exception'    => [
                        'class'   => get_class($e),
                        'file'    => $e->getFile(),
                        'line'    => $e->getLine(),
                    ]
                    ]),
                    'extra'       => json_encode([
                        'trace' => $e->getTraceAsString(),
                    ]),
                    'created_at' => $logdate
                ]
            );
            $this->container->get('flash')->addMessage('error', 'Zone record ' . $data['action'] . ' failed. Please try again later');
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

            try {
                $service = new Service($pdo);
                $domainOrder = [
                    'config' => json_encode($config),
                ];
                $service->deleteDomain($domainOrder);
            } catch (\RuntimeException $e) {
                $currentDateTime = new \DateTime();
                $logdate = $currentDateTime->format('Y-m-d H:i:s.v');
                $db->insert(
                    'error_log',
                    [
                        'channel' => 'domain_manager',
                        'level' => 400,
                        'level_name' => 'ERROR',
                        'message' => "Unexpected failure during zone deletion: " . $e->getMessage(),
                        'context' => json_encode([
                            'user_id' => $_SESSION['auth_user_id'] ?? null, 
                            'domain' => $args ?? null, 
                            'provider' => $providerDisplay ?? null,
                            'exception'    => [
                                'class'   => get_class($e),
                                'file'    => $e->getFile(),
                                'line'    => $e->getLine(),
                            ]
                        ]),
                        'extra'       => json_encode([
                            'trace' => $e->getTraceAsString(),
                        ]),
                        'created_at' => $logdate
                    ]
                );
                $this->container->get('flash')->addMessage('error', 'Zone deletion failed. Please try again later');
                return $response->withHeader('Location', '/zones')->withStatus(302);
            } catch (\Throwable $e) {
                $currentDateTime = new \DateTime();
                $logdate = $currentDateTime->format('Y-m-d H:i:s.v');
                $db->insert(
                    'error_log',
                    [
                        'channel' => 'domain_manager',
                        'level' => 400,
                        'level_name' => 'ERROR',
                        'message' => "Unexpected failure during zone deletion: " . $e->getMessage(),
                        'context' => json_encode([
                            'user_id' => $_SESSION['auth_user_id'] ?? null, 
                            'domain' => $args ?? null, 
                            'provider' => $providerDisplay ?? null,
                            'exception'    => [
                                'class'   => get_class($e),
                                'file'    => $e->getFile(),
                                'line'    => $e->getLine(),
                            ]
                        ]),
                        'extra'       => json_encode([
                            'trace' => $e->getTraceAsString(),
                        ]),
                        'created_at' => $logdate
                    ]
                );
                $this->container->get('flash')->addMessage('error', 'Zone deletion failed. Please try again later');
                return $response->withHeader('Location', '/zones')->withStatus(302);
            }

            $this->container->get('flash')->addMessage('success', 'Zone ' . $args . ' deleted successfully');
            return $response->withHeader('Location', '/zones')->withStatus(302);
        } else {
            // Redirect to the domains view
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }
    }

}