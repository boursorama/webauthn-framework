<?php

declare(strict_types=1);

namespace Webauthn;

use Webauthn\Exception\InvalidDataException;

class CollectedAssetLinks
{
    /**
     * @var mixed[]
     */
    private readonly array $data;

    /**
     * @var CollectedAssetLink[]
     */
    private readonly array $assetLinks;

    /**
     * @param mixed[] $data
     */
    public function __construct(
        private readonly string $rawData,
        array $data
    ) {
        $this->assetLinks = [];
        foreach ($data as $assetLink) {
            $this->assetLinks[] = new CollectedAssetLink($assetLink);
        }

        $this->data = $data;
    }

    public static function createFromJson(string $data): self
    {
        $json = json_decode($data, true, 512, JSON_THROW_ON_ERROR);

        return new self($data, $json);
    }

    /**
     * @return CollectedAssetLink[]
     */
    public function getAssetLinks(): array
    {
        return $this->assetLinks;
    }

    /**
     * @return string[]
     */
    public function all(): array
    {
        return array_keys($this->data);
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    public function get(string $key): mixed
    {
        if (!$this->has($key)) {
            throw InvalidDataException::create($this->data, sprintf('The key "%s" is missing', $key));
        }

        return $this->data[$key];
    }
}

class CollectedAssetLink
{
    /** @var string[] */
    private readonly array $relation;

    private readonly string $targetNamespace;

    private readonly ?string $targetPackageName;

    /** @var string[]|null */
    private readonly ?array $targetSha256CertFingerPrints;

    private readonly ?string $targetSite;

    /**
     * @param mixed[] $data
     */
    public function __construct(
        array $data
    ) {
        $relation = $data['relation'] ?? null;
        is_array($relation) || throw InvalidDataException::create(
            $data,
            'Invalid parameter "relation". Shall be an array.'
        );
        $this->relation = $relation;

        $target = $data['target'] ?? [];
        (is_array($target) && !empty($target)) || throw InvalidDataException::create(
            $data,
            'Invalid parameter "target". Shall be a non-empty array.'
        );

        $namespace = $target['namespace'] ?? '';
        (is_string($namespace) && $namespace !== '') || throw InvalidDataException::create(
            $data,
            'Invalid parameter "namespace". Shall be a non-empty string.'
        );
        $this->targetNamespace = $namespace;

        $packageName = $target['package_name'] ?? null;
        (is_string($packageName) && $packageName !== '') || $packageName === null || throw InvalidDataException::create(
            $data,
            'Invalid parameter "package_name". Shall be a non-empty string or null.'
        );
        $this->targetNamespace = $packageName;

        $sha256CertFingerPrints = $target['sha256_cert_fingerprints'] ?? null;
        is_array($sha256CertFingerPrints) || $sha256CertFingerPrints === null || throw InvalidDataException::create(
            $data,
            'Invalid parameter "sha256_cert_fingerprints". Shall be an array of string or null.'
        );
        $this->targetSha256CertFingerPrints = $sha256CertFingerPrints;

        $targetSite = $target['site'] ?? null;
        is_string($targetSite) || $targetSite === null || throw InvalidDataException::create(
            $data,
            'Invalid parameter "site". Shall be a string or null.'
        );
    }

    public function getRelation(): array
    {
        return $this->relation;
    }

    public function getTargetNamespace(): string
    {
        return $this->targetNamespace;
    }

    public function getTargetPackageName(): ?string
    {
        return $this->targetPackageName;
    }

    public function getTargetSha256CertFingerPrints(): ?array
    {
        return $this->targetSha256CertFingerPrints;
    }

    public function getTargetSite(): ?string
    {
        return $this->targetSite;
    }
}
