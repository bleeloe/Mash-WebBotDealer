<?php
use Jaybizzle\CrawlerDetect\CrawlerDetect;

class BotDetector
{
    protected $ipinfoToken;

    public function __construct($ipinfoToken = null)
    {
        $this->ipinfoToken = $ipinfoToken;
    }

    public function analyzeRequest($server)
    {
        $userAgent = $server['HTTP_USER_AGENT'] ?? '';
        $ip = $server['REMOTE_ADDR'] ?? '0.0.0.0';
        $referer = $server['HTTP_REFERER'] ?? '-';
        $headers = function_exists('getallheaders') ? getallheaders() : [];

        $crawlerDetect = new CrawlerDetect();

        $type = 'HUMAN';
        $flags = [];

        // 1. User-Agent check
        if ($crawlerDetect->isCrawler($userAgent)) {
            $type = 'BOT';
            $flags[] = 'ua_bot';
        }

        // 2. Reverse DNS check
        $hostname = gethostbyaddr($ip);
        if ($hostname && $hostname !== $ip) {
            if (preg_match('/googlebot\.com|search\.msn\.com|crawl\.facebook\.com/i', $hostname)) {
                $flags[] = 'dns_verified';
                $type = 'BOT';
            }
        }

        // 3. IP ASN check (via ipinfo.io)
        $asn = '-';
        if ($this->ipinfoToken) {
            $asn = $this->lookupASN($ip);
            if ($asn && preg_match('/(amazon|aws|ec2|google cloud|gcp|microsoft|azure|ovh|soyoustart|kimsufi|digitalocean|do-?droplet|linode|vultr|vultrusercontent|hetzner|online.net|scaleway|leaseweb|m247|contabo|choopa|shinjiru|upcloud|ionos|1and1|netcup|hostwinds|kamatera|ramnode|interserver|hivelocity|quadra|cloudsigma|bandwagon|alphavps|shinjiru|terrahost|uccloud|colo|datacamp|phoenixnap|cloudways)/i', $asn)) {
                $flags[] = 'datacenter';
                if ($type !== 'BOT') {
                    $type = 'SUSPECT';
                }
            }
        }


        // 4. Header heuristic
        if (!isset($headers['Accept-Language'])) {
            $flags[] = 'missing_accept_language';
            if ($type === 'HUMAN') {
                $type = 'SUSPECT';
            }
        }

        // cek urutan secara umum di browser
        if (!isset($headers['Sec-Ch-Ua'])) {
            $flags[] = 'missing_ch_ua';
            $type = 'SUSPECT';
        }

        if (stripos($userAgent, 'curl') !== false || stripos($userAgent, 'python') !== false) {
            $flags[] = 'script_client';
            $type = 'BOT';
        }

        return [
            'datetime' => date('Y-m-d H:i:s'),
            'ip' => $ip,
            'type' => $type,
            'ua' => $userAgent,
            'ref' => $referer,
            'asn' => $asn,
            'hostname' => $hostname,
            'flags' => implode(';', $flags),
        ];
    }

    protected function lookupASN($ip)
    {
        $url = "https://ipinfo.io/{$ip}/org?token={$this->ipinfoToken}";
        $ctx = stream_context_create(['http' => ['timeout' => 2]]);
        return @file_get_contents($url, false, $ctx) ?: '-';
    }
}
