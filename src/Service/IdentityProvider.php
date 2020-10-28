<?php


namespace App\Service;


use Doctrine\DBAL\Exception;
use OneLogin\Saml2\Auth as OneLogin_Saml2_Auth;
use OneLogin\Saml2\Error;
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
                'x509cert' => file_get_contents('../config/certs/onelogin.pem'),
                'privateKey' => file_get_contents('../config/certs/onelogin.pem'),
            ),
            'idp' => array(
                'entityId' => $idpEntityId,
                'singleSignOnService' => array(
                    'url' => $ssoUrl,
                ),
                'singleLogoutService' => array(
                    'url' => $slsUrl,
                ),
                'x509cert' => file_get_contents('../config/certs/onelogin.pem'),
            ),
        ];
    }

    /**
     * @return OneLogin_Saml2_Auth
     * @throws Error
     */
    public function auth()
    {
        return new OneLogin_Saml2_Auth($this->configuration);
    }

    /**
     * @return OneLogin_Saml2_Settings
     * @throws Error
     */
    public function settings()
    {
        return new OneLogin_Saml2_Settings($this->configuration, true);
    }

    /**
     * @param OneLogin_Saml2_Auth $auth
     * @return string
     * @throws Error
     * @throws Exception
     */
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