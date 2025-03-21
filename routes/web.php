<?php

use App\Controllers\Auth\AuthController;
use App\Controllers\Auth\PasswordController;
use App\Controllers\HomeController;
use App\Controllers\ZonesController;
use App\Controllers\LogsController;
use App\Controllers\UsersController;
use App\Controllers\ReportsController;
use App\Controllers\ProfileController;
use App\Controllers\SystemController;
use App\Controllers\DapiController;
use App\Middleware\AuthMiddleware;
use App\Middleware\GuestMiddleware;
use Slim\Exception\HttpNotFoundException;
use Nyholm\Psr7\ServerRequest;
use Nyholm\Psr7\Response;
use Tqdev\PhpCrudApi\Api;
use Tqdev\PhpCrudApi\Config\Config;

$app->get('/', HomeController::class .':index')->setName('index');

$app->group('', function ($route) {
    $route->get('/login', AuthController::class . ':createLogin')->setName('login');
    $route->map(['GET', 'POST'], '/login/verify', AuthController::class . ':verify2FA')->setName('verify2FA');
    $route->post('/login', AuthController::class . ':login');
    $route->post('/webauthn/login/challenge', AuthController::class . ':getLoginChallenge')->setName('webauthn.login.challenge');
    $route->post('/webauthn/login/verify', AuthController::class . ':verifyLogin')->setName('webauthn.login.verify');
    $route->get('/forgot-password', PasswordController::class . ':createForgotPassword')->setName('forgot.password');
    $route->post('/forgot-password', PasswordController::class . ':forgotPassword');
    $route->get('/reset-password', PasswordController::class.':resetPassword')->setName('reset.password');
    $route->get('/update-password', PasswordController::class.':createUpdatePassword')->setName('update.password');
    $route->post('/update-password', PasswordController::class.':updatePassword');
    $route->post('/webhook/adyen', FinancialsController::class .':webhookAdyen')->setName('webhookAdyen');
})->add(new GuestMiddleware($container));

$app->group('', function ($route) {
    $route->get('/dashboard', HomeController::class .':dashboard')->setName('home');

    $route->get('/zones', ZonesController::class .':listZones')->setName('listZones');
    $route->map(['GET', 'POST'], '/zone/check', ZonesController::class . ':checkZone')->setName('checkZone');
    $route->map(['GET', 'POST'], '/zone/create', ZonesController::class . ':createZone')->setName('createZone');
    $route->get('/zone/view/{zone}', ZonesController::class . ':viewZone')->setName('viewZone');
    $route->get('/zone/update/{zone}', ZonesController::class . ':updateZone')->setName('updateZone');
    $route->post('/zone/update', ZonesController::class . ':updateZoneProcess')->setName('updateZoneProcess');
    $route->post('/zone/updaterecord', ZonesController::class . ':zoneUpdateRecord')->setName('zoneUpdateRecord');
    $route->map(['GET', 'POST'], '/zone/delete/{zone}', ZonesController::class . ':deleteZone')->setName('deleteZone');
    
    $route->get('/users', UsersController::class .':listUsers')->setName('listUsers');
    $route->map(['GET', 'POST'], '/user/create', UsersController::class . ':createUser')->setName('createUser');
    $route->get('/user/update/{user}', UsersController::class . ':updateUser')->setName('updateUser');
    $route->post('/user/update', UsersController::class . ':updateUserProcess')->setName('updateUserProcess');

    $route->get('/log', LogsController::class .':log')->setName('log');

    $route->get('/server', ReportsController::class .':serverHealth')->setName('serverHealth');
    $route->post('/clear-cache', ReportsController::class .':clearCache')->setName('clearCache');

    $route->map(['GET', 'POST'], '/providers', SystemController::class .':providers')->setName('providers');

    $route->get('/profile', ProfileController::class .':profile')->setName('profile');
    $route->post('/profile/2fa', ProfileController::class .':activate2fa')->setName('activate2fa');
    $route->post('/profile/logout-everywhere', ProfileController::class . ':logoutEverywhereElse')->setName('profile.logout.everywhere');
    $route->get('/webauthn/register/challenge', ProfileController::class . ':getRegistrationChallenge')->setName('webauthn.register.challenge');
    $route->post('/webauthn/register/verify', ProfileController::class . ':verifyRegistration')->setName('webauthn.register.verify');
    $route->post('/token-well', ProfileController::class .':tokenWell')->setName('tokenWell');

    $route->get('/mode', HomeController::class .':mode')->setName('mode');
    $route->get('/lang', HomeController::class .':lang')->setName('lang');
    $route->get('/logout', AuthController::class . ':logout')->setName('logout');
    $route->post('/change-password', PasswordController::class . ':changePassword')->setName('change.password');

    $route->get('/dapi/zones', [DapiController::class, 'listZones']);
})->add(new AuthMiddleware($container));

$app->any('/api[/{params:.*}]', function (
    ServerRequest $request,
    Response $response,
    $args
) use ($container) {
    $db = config('connections');
    if (config('default') == 'mysql') {
        $db_username = $db['mysql']['username'];
        $db_password = $db['mysql']['password'];
        $db_database = $db['mysql']['database'];
        $db_address = 'localhost';
    } elseif (config('default') == 'pgsql') {
        $db_username = $db['pgsql']['username'];
        $db_password = $db['pgsql']['password'];
        $db_database = $db['pgsql']['database'];
        $db_address = 'localhost';
    } elseif (config('default') == 'sqlite') {
        $db_username = null;
        $db_password = null;
        $db_database = null;
        $db_address = '/var/www/cp/registry.db';
    }
    $config = new Config([
        'driver' => config('default'),
        'username' => $db_username,
        'password' => $db_password,
        'database' => $db_database,
        'address' => $db_address,
        'basePath' => '/api',
        'middlewares' => 'customization,dbAuth,authorization,sanitation,multiTenancy',
        'authorization.tableHandler' => function ($operation, $tableName) {
        $restrictedTables = ['contact_authInfo', 'contact_postalInfo', 'domain_authInfo', 'secdns'];
            return !in_array($tableName, $restrictedTables);
        },
        'authorization.columnHandler' => function ($operation, $tableName, $columnName) {
            if ($tableName == 'registrar' && $columnName == 'pw') {
                return false;
            }
            if ($tableName == 'users' && $columnName == 'password') {
                return false;
            }
            return true;
        },
        'sanitation.handler' => function ($operation, $tableName, $column, $value) {
            return is_string($value) ? strip_tags($value) : $value;
        },
        'customization.beforeHandler' => function ($operation, $tableName, $request, $environment) {
            if (!isset($_SESSION['auth_logged_in']) || $_SESSION['auth_logged_in'] !== true) {
                header('HTTP/1.1 401 Unauthorized');
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode(['error' => 'Authentication required']);
                exit;
            }
            $_SESSION['user'] = $_SESSION['auth_username'];
        },
        'customization.afterHandler' => function ($operation, $tableName, $response, $environment) {
            $bodyContent = (string) $response->getBody();
            $response->getBody()->rewind();
            $data = json_decode($bodyContent, true);

            if ($tableName == 'domain') {
                if (isset($data['records']) && is_array($data['records'])) {
                    foreach ($data['records'] as &$record) {
                        if (isset($record['name']) && stripos($record['name'], 'xn--') === 0) {
                            $record['name_o'] = $record['name'];
                            $record['name'] = idn_to_utf8($record['name'], 0, INTL_IDNA_VARIANT_UTS46);
                        } else {
                            $record['name_o'] = $record['name'];
                        }
                    }
                    unset($record);
                }
            }
            else if ($tableName == 'domain_tld') {
                if (isset($data['records']) && is_array($data['records'])) {
                    foreach ($data['records'] as &$record) {
                        if (isset($record['tld']) && stripos($record['tld'], '.xn--') === 0) {
                            $punycodeTld = ltrim($record['tld'], '.');
                            $record['tld_o'] = $record['tld'];
                            $record['tld'] = '.'.idn_to_utf8(strtolower($punycodeTld), 0, INTL_IDNA_VARIANT_UTS46);
                        } else {
                            $record['tld_o'] = $record['tld'];
                        }
                    }
                    unset($record);
                }
            }

            $modifiedBodyContent = json_encode($data, JSON_UNESCAPED_UNICODE);
            $stream = \Nyholm\Psr7\Stream::create($modifiedBodyContent);
            $response = $response->withBody($stream);
            $response = $response->withHeader('Content-Length', strlen($modifiedBodyContent));
            return $response;
        },
        'dbAuth.usersTable' => 'users',
        'dbAuth.usernameColumn' => 'email',
        'dbAuth.passwordColumn' => 'password',
        'dbAuth.returnedColumns' => 'email,roles_mask',
        'dbAuth.registerUser' => false,
        'multiTenancy.handler' => function ($operation, $tableName) {   
            if (isset($_SESSION['auth_roles']) && $_SESSION['auth_roles'] === 0) {
                return [];
            }
            $registrarId = $_SESSION['auth_registrar_id'];

            $columnMap = [
                'zone' => 'client_id',
                'poll' => 'registrar_id',
                'registrar' => 'id',
                'users_audit' => 'user_id', // Continues to use user_id
            ];

            // Check if the special filter condition for the domain table is met
            $isSpecialDomainRequest = $tableName === 'domain' && isset($_GET['filter']) && $_GET['filter'] === 'trstatus,nis';

            if (array_key_exists($tableName, $columnMap)) {
                // If it's a special domain request, bypass the usual filtering
                if ($isSpecialDomainRequest) {
                    return [];
                }

                // Use registrarId for tables where 'registrar_id' is the filter
                // For 'support_tickets' and 'users_audit', use userId
                return [$columnMap[$tableName] => (in_array($tableName, ['support_tickets', 'users_audit']) ? $_SESSION['auth_user_id'] : $registrarId)];
            }

            return ['1' => '0'];
        },
    ]);
    $api = new Api($config);
    $response = $api->handle($request);
    return $response;
});

$app->add(function (Psr\Http\Message\ServerRequestInterface $request, Psr\Http\Server\RequestHandlerInterface $handler) {
    try {
        return $handler->handle($request);
    } catch (HttpNotFoundException $e) {
        $responseFactory = new \Nyholm\Psr7\Factory\Psr17Factory();
        $response = $responseFactory->createResponse();
        return $response
            ->withHeader('Location', '/')
            ->withStatus(302);
    }
});

$app->addErrorMiddleware(true, true, true);