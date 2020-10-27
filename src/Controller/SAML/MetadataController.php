<?php


namespace App\Controller\SAML;


use Exception;
use OneLogin\Saml2\Error as OneLogin_Saml2_Error;
use OneLogin\Saml2\Settings as OneLogin_Saml2_Settings;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class MetadataController
{
    /**
     * @var string
     */
    private $spBaseUrl;
    /**
     * @var array[]
     */
    private $configuration_bundle;

    public function __construct(string $baseUrl, string $idpEntityId, string $ssoUrl, string $slsUrl, string $idpCert)
    {
        //Not a good practice, I know
        $this->spBaseUrl = $baseUrl;
        $this->configuration_bundle = [
            'sp' => array(
                'entityId' => $this->spBaseUrl . '/metadata',
                'assertionConsumerService' => array(
                    'url' => $this->spBaseUrl . '/saml?acs',
                ),
                'singleLogoutService' => array(
                    'url' => $this->spBaseUrl . '/saml?sls',
                ),
                'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
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

    /**
     * @Route("/metadata", name="metadata")
     */
    public function metadata()
    {
        try {
            #$auth = new OneLogin_Saml2_Auth($settingsInfo);
            #$settings = $auth->getSettings();
            // Now we only validate SP settings
            $settings = new OneLogin_Saml2_Settings($this->configuration_bundle, true);
            $metadata = $settings->getSPMetadata();
            $errors = $settings->validateMetadata($metadata);
            if (!empty($errors)) {
                throw new OneLogin_Saml2_Error(
                    'Invalid SP metadata: ' . implode(', ', $errors),
                    OneLogin_Saml2_Error::METADATA_SP_INVALID
                );
            }
        } catch (Exception $e) {
            return $e->getMessage();
        }
        header('Content-Type: text/xml');
        return new Response($metadata);
    }
}