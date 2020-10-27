<?php


namespace App\Controller\SAML;


use App\Service\IdentityProvider;
use Exception;
use OneLogin\Saml2\Error as OneLogin_Saml2_Error;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class MetadataController
{
    /**
     * @var IdentityProvider
     */
    private $identityProviderService;

    /**
     * MetadataController constructor.
     * @param IdentityProvider $identityProviderService
     */
    public function __construct(IdentityProvider $identityProviderService)
    {
        $this->identityProviderService = $identityProviderService;
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
            $settings = $this->identityProviderService->settings();
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
        //header('Content-Type: text/xml');
        return new Response($metadata);
    }
}