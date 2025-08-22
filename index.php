<?php
require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/tools/BotDetector.php';
require __DIR__ . '/tools/Logger.php';

use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

$botPage = $_ENV['BOT_PAGE'] ?? '/page-for-bot';
$humanPage = $_ENV['HUMAN_PAGE'] ?? '/landing-page';
$logDir = $_ENV['LOG_DIR'] ?? __DIR__ . '/logs/';

var_dump($_SERVER);
die;

// --- Jalankan deteksi ---
$detector = new BotDetector($_ENV['IPINFO_TOKEN'] ?? null);
$result = $detector->analyzeRequest($_SERVER);


// --- Logging ---
$logger = new TrafficLogger($logDir);
$logger->log($result);



// --- Routing to output ---
if ($result['type'] === 'BOT' || $result['type'] === 'SUSPECT') {
    header("Location: {$botPage}");
    exit;
} else {
    header("Location: {$humanPage}");
    exit;
}
