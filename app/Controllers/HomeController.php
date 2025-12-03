<?php
/**
 * Argora Foundry
 *
 * A modular PHP boilerplate for building SaaS applications, admin panels, and control systems.
 *
 * @package    App
 * @author     Taras Kondratyuk <help@argora.org>
 * @copyright  Copyright (c) 2025 Argora
 * @license    MIT License
 * @link       https://github.com/getargora/foundry
 */

namespace App\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Container\ContainerInterface;

class HomeController extends Controller
{
    public function index(Request $request, Response $response)
    {
        return view($response,'index.twig');
    }

    public function dashboard(Request $request, Response $response)
    {
        $db = $this->container->get('db');
        $isAdmin = $_SESSION["auth_roles"] == 0;
        $userId = $_SESSION["auth_user_id"];
        
        if ($isAdmin) {
            // Admin: total counts
            $userCount = $db->selectValue('SELECT COUNT(*) FROM users');
            $zoneCount = $db->selectValue('SELECT COUNT(*) FROM zones');
            $ticketCount = $db->selectValue('SELECT COUNT(*) FROM support_tickets');

            $openTickets = $db->selectValue('SELECT COUNT(*) FROM support_tickets WHERE status = ?', ['Open']);
        } else {
            // Regular user: filtered by user_id
            $userCount = null; // Don't send this to view for users
            $zoneCount = $db->selectValue('SELECT COUNT(*) FROM zones WHERE client_id = ?', [$userId]);
            $ticketCount = $db->selectValue('SELECT COUNT(*) FROM support_tickets WHERE user_id = ?', [$userId]);

            $openTickets = $db->selectValue('SELECT COUNT(*) FROM support_tickets WHERE user_id = ? AND status = ?', [$userId, 'Open']);
        }

        return view($response, 'admin/dashboard/index.twig', [
            'userCount' => $userCount,
            'zoneCount' => $zoneCount,
            'ticketCount' => $ticketCount,
            'openTickets' => $openTickets
        ]);
    }

    public function mode(Request $request, Response $response)
    {
        if (isset($_SESSION['_screen_mode']) && $_SESSION['_screen_mode'] == 'dark') {
            $_SESSION['_screen_mode'] = 'light';
        } else {
            $_SESSION['_screen_mode'] = 'dark';
        }
        $referer = $request->getHeaderLine('Referer');
        if (!empty($referer)) {
            return $response->withHeader('Location', $referer)->withStatus(302);
        }
        return $response->withHeader('Location', '/dashboard')->withStatus(302);
    }

    public function lang(Request $request, Response $response)
    {
        $data = $request->getQueryParams();
        if (!empty($data)) {
            $_SESSION['_lang'] = array_key_first($data);
        } else {
            unset($_SESSION['_lang']);
        }
        $referer = $request->getHeaderLine('Referer');
        if (!empty($referer)) {
            return $response->withHeader('Location', $referer)->withStatus(302);
        }
        return $response->withHeader('Location', '/dashboard')->withStatus(302);
    }

    public function selectTheme(Request $request, Response $response)
    {
        global $container;

        $data = $request->getParsedBody();
        $_SESSION['_theme'] = ($v = substr(trim(preg_replace('/[^\x20-\x7E]/', '', $data['theme-primary'] ?? '')), 0, 30)) !== '' ? $v : 'blue';

        $container->get('flash')->addMessage('success', 'Theme color has been set successfully');
        return $response->withHeader('Location', '/profile')->withStatus(302);
    }
}