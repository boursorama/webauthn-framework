<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Webauthn\MetadataService\CanLogData;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * This dummy Public Key User Entity Repository is set to allow the bundle to be installed even if the real repository
 * is not set in the configuration file. This class shall be replaced in favour of your own implementation.
 */
class DummyPublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepositoryInterface, CanLogData
{
    public function __construct(
        private LoggerInterface $logger = new NullLogger()
    ) {
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    public function findOneByUsername(string $username): ?PublicKeyCredentialUserEntity
    {
        $this->logger->critical(
            'Please change the Public Key Credential User Entity Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1'
        );
        throw new RuntimeException(
            'You are using the DummyPublicKeyCredentialUserEntityRepository service. Please create your own repository'
        );
    }

    public function findOneByUserHandle(string $userHandle): ?PublicKeyCredentialUserEntity
    {
        $this->logger->critical(
            'Please change the Public Key Credential User Entity Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1'
        );
        throw new RuntimeException(
            'You are using the DummyPublicKeyCredentialUserEntityRepository service. Please create your own repository'
        );
    }
}
