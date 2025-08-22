<?php
use Monolog\Logger;
use Monolog\Handler\RotatingFileHandler;
use Monolog\Formatter\LineFormatter;

class TrafficLogger
{
    protected $logger;

    public function __construct($logDir)
    {
        if (!is_dir($logDir)) {
            mkdir($logDir, 0777, true);
        }

        $this->logger = new Logger('traffic');

        // Rotating file: 30 hari
        $handler = new RotatingFileHandler($logDir . '/traffic.log', 30, Logger::INFO);

        // Format CSV        
        $output = "%datetime%,%context.ip%,%context.type%,\"%context.ua%\",\"%context.ref%\",\"%context.asn%\",\"%context.hostname%\",\"%context.flags%\"\n";
        $formatter = new LineFormatter($output, 'Y-m-d H:i:s', true, true);
        $handler->setFormatter($formatter);

        $this->logger->pushHandler($handler);
    }

    public function log(array $data)
    {            
        $this->logger->info('visit', $data);
    }
}
