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

class SparkController extends Controller
{
    public function listZones(Request $request, Response $response): Response
    {
        $params = $request->getQueryParams();
        $db = $this->container->get('db');

        // Map fields to fully qualified columns
        $allowedFieldsMap = [
            'domain_name' => 'd.domain_name',
            'created_at' => 'd.created_at',
            'updated_at' => 'd.updated_at'
        ];

        // --- SORTING ---
        $sortField = 'd.created_at'; // default
        $sortDir = 'desc';
        if (!empty($params['order'])) {
            $orderParts = explode(',', $params['order']);
            if (count($orderParts) === 2) {
                $fieldCandidate = preg_replace('/[^a-zA-Z0-9_]/', '', $orderParts[0]);
                if (array_key_exists($fieldCandidate, $allowedFieldsMap)) {
                    $sortField = $allowedFieldsMap[$fieldCandidate];
                }
                $sortDir = strtolower($orderParts[1]) === 'asc' ? 'asc' : 'desc';
            }
        }

        // --- PAGINATION ---
        $page = 1;
        $size = 10;
        if (!empty($params['page'])) {
            $pageParts = explode(',', $params['page']);
            if (count($pageParts) === 2) {
                $pageNum = (int)$pageParts[0];
                $pageSize = (int)$pageParts[1];
                if ($pageNum > 0) {
                    $page = $pageNum;
                }
                if ($pageSize > 0) {
                    $size = $pageSize;
                }
            }
        }
        $offset = ($page - 1) * $size;

        // --- FILTERING ---
        $whereClauses = [];
        $bindParams = [];
        foreach ($params as $key => $value) {
            if (preg_match('/^filter\d+$/', $key)) {
                $fParts = explode(',', $value);
                if (count($fParts) === 3) {
                    list($fField, $fOp, $fVal) = $fParts;
                    $fField = preg_replace('/[^a-zA-Z0-9_]/', '', $fField);

                    // Ensure the field is allowed and fully qualify it
                    if (!array_key_exists($fField, $allowedFieldsMap)) {
                        // Skip unknown fields
                        continue;
                    }
                    $column = $allowedFieldsMap[$fField];

                    switch ($fOp) {
                        case 'eq':
                            $whereClauses[] = "$column = :f_{$key}";
                            $bindParams["f_{$key}"] = $fVal;
                            break;
                        case 'cs':
                            // If searching in 'domain_name' and user might enter Cyrillic
                            if ($fField === 'domain_name') {
                                // Convert to punycode
                                $punyVal = idn_to_ascii($fVal, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);
                                if ($punyVal !== false && $punyVal !== $fVal) {
                                    // Search for both punycode and original term
                                    // (d.domain_name LIKE '%cyrillic%' OR d.domain_name LIKE '%punycode%')
                                    $whereClauses[] = "($column LIKE :f_{$key}_original OR $column LIKE :f_{$key}_puny)";
                                    $bindParams["f_{$key}_original"] = "%$fVal%";
                                    $bindParams["f_{$key}_puny"] = "%$punyVal%";
                                } else {
                                    // Just search normally
                                    $whereClauses[] = "$column LIKE :f_{$key}";
                                    $bindParams["f_{$key}"] = "%$fVal%";
                                }
                            } else {
                                // Non-domain_name field, just search as usual
                                $whereClauses[] = "$column LIKE :f_{$key}";
                                $bindParams["f_{$key}"] = "%$fVal%";
                            }
                            break;
                        case 'sw':
                            $whereClauses[] = "$column LIKE :f_{$key}";
                            $bindParams["f_{$key}"] = "$fVal%";
                            break;
                        case 'ew':
                            $whereClauses[] = "$column LIKE :f_{$key}";
                            $bindParams["f_{$key}"] = "%$fVal";
                            break;
                        // Add other cases if needed
                    }
                }
            }
        }

        // Check admin status and apply user filter if needed
        $userCondition = '';

        $userId   = isset($_SESSION['auth_user_id']) ? (int) $_SESSION['auth_user_id'] : 0;
        $userRole = isset($_SESSION['auth_roles']) ? (int) $_SESSION['auth_roles'] : 0;

        if ($userRole !== 0 && $userId > 0) {
            $userCondition = "d.client_id = :userId";
            $bindParams['userId'] = $userId;
        }

        // Base SQL
        $sqlBase = "
            FROM zones d
        ";

        // Combine user condition and search filters
        if (!empty($whereClauses)) {
            // We have search conditions
            $filtersCombined = "(" . implode(" OR ", $whereClauses) . ")";
            if ($userCondition) {
                // If userCondition exists and we have filters
                // we do userCondition AND (filters OR...)
                $sqlWhere = "WHERE $userCondition AND $filtersCombined";
            } else {
                // No user restriction, just the filters
                $sqlWhere = "WHERE $filtersCombined";
            }
        } else {
            // No search filters
            if ($userCondition) {
                // Only user condition
                $sqlWhere = "WHERE $userCondition";
            } else {
                // No filters, no user condition
                $sqlWhere = '';
            }
        }

        // Count total results
        $totalSql = "SELECT COUNT(DISTINCT d.id) AS total $sqlBase $sqlWhere";
        $totalCount = $db->selectValue($totalSql, $bindParams);

        // Data query
        $selectFields = "
            d.id, 
            d.domain_name, 
            d.config, 
            d.created_at, 
            d.updated_at
        ";

        $dataSql = "
            SELECT $selectFields
            $sqlBase
            $sqlWhere
            GROUP BY d.id
            ORDER BY $sortField $sortDir
            " . $this->limitClause($offset, $size) . "
        ";

        $records = $db->select($dataSql, $bindParams);

        // Ensure records is always an array
        if (!$records) {
            $records = [];
        }

        // Format API results
        foreach ($records as &$row) {
            // Check if domain_name is punycode by checking if it starts with 'xn--'
            if (stripos($row['domain_name'], 'xn--') === 0) {
                // Convert punycode to Unicode and store it in 'domain_name'
                $unicode_name = idn_to_utf8($row['domain_name'], IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);
                $row['domain_name_o'] = $row['domain_name']; // Keep the original punycode in 'domain_name_o'
                $row['domain_name'] = $unicode_name; // Store the Unicode version in 'domain_name'
            } else {
                // For regular names, both 'domain_name' and 'domain_name_o' are the same
                $row['domain_name_o'] = $row['domain_name'];
            }

            // Extract provider from JSON config
            if (!empty($row['config'])) {
                $configData = json_decode($row['config'], true); // Decode JSON
                $row['config'] = $configData['provider'] ?? "N/A"; // Keep only provider value or default
            } else {
                $row['config'] = "N/A"; // Default for empty config
            }
        }

        $payload = [
            'records' => $records,
            'results' => $totalCount
        ];

        $response = $response->withHeader('Content-Type', 'application/json; charset=UTF-8');
        $response->getBody()->write(json_encode($payload, JSON_UNESCAPED_UNICODE));
        return $response;
    }

    private function limitClause(int $offset, int $size): string
    {
        // harden numbers
        $offset = max(0, (int)$offset);
        $size   = max(1, (int)$size);

        switch (envi('DB_DRIVER')) {
            case 'mysql':
                // MySQL/MariaDB
                return "LIMIT {$offset}, {$size}";
            case 'pgsql':
            case 'sqlite':
            default:
                // PostgreSQL & SQLite
                return "LIMIT {$size} OFFSET {$offset}";
        }
    }

}