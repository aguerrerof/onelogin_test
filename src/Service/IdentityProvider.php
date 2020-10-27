<?php


namespace App\Service;


use Doctrine\DBAL\Exception;
use OneLogin\Saml2\Auth as OneLogin_Saml2_Auth;
use OneLogin\Saml2\Settings as OneLogin_Saml2_Settings;

class IdentityProvider
{
    /**
     * @var string
     */
    private $serviceProviderUrl;
    /**
     * @var array[]
     */
    private $configuration;

    /**
     * IdentityProvider constructor.
     * @param string $baseUrl
     * @param string $nameIdFormat
     * @param string $idpEntityId
     * @param string $ssoUrl
     * @param string $slsUrl
     * @param string $idpCert
     * @param false $debug
     * @param false $strict
     */
    public function __construct(string $baseUrl, string $nameIdFormat, string $idpEntityId, string $ssoUrl, string $slsUrl, string $idpCert, $debug = false, $strict = false)
    {
        $this->serviceProviderUrl = $baseUrl;
        $this->configuration = [
            'debug' => $debug,
            'strict' => $strict,
            'sp' => array(
                'entityId' => $this->serviceProviderUrl . '/metadata',
                'assertionConsumerService' => array(
                    'url' => $this->serviceProviderUrl . '/saml?acs',
                ),
                'singleLogoutService' => array(
                    'url' => $this->serviceProviderUrl . '/saml?sls',
                ),
                'NameIDFormat' => $nameIdFormat,
            ),
            'idp' => array(
                'entityId' => $idpEntityId,
                'singleSignOnService' => array(
                    'url' => $ssoUrl,
                ),
                'singleLogoutService' => array(
                    'url' => $slsUrl,
                ),
                'x509cert' => $idpCert,
            ),
        ];
    }

    public function auth()
    {
        return new OneLogin_Saml2_Auth($this->configuration);
    }

    public function settings()
    {
        return new OneLogin_Saml2_Settings($this->configuration, true);
    }

    public function getSSOUrl(OneLogin_Saml2_Auth $auth)
    {
        $ssoBuiltUrl = $auth->login(null, array(), false, false, true);
        if (is_null($ssoBuiltUrl)) {
            throw new Exception("Failed building URL process");
        }
        return $ssoBuiltUrl;
    }

    /**
     * @return string
     */
    public function getServiceProviderUrl(): string
    {
        return $this->serviceProviderUrl;
    }

    /**
     * @return array[]
     */
    public function getConfiguration(): array
    {
        return $this->configuration;
    }

}