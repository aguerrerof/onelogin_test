<?php


namespace App\Controller\SAML;


use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class AttributesController
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
                    'url' =>$slsUrl,
                ),
                'x509cert' => $idpCert,
            ),
        ];
    }

    /**
     * @Route("/attributes", name="attributes")
     */
    public function index()
    {
        if (!isset($_SESSION)) {
            session_start();
        }
        $response = "";
        if (isset($_SESSION['samlUserdata'])) {
            if (!empty($_SESSION['samlUserdata'])) {
                $attributes = $_SESSION['samlUserdata'];
                $response .= 'You have the following attributes:<br>';
                $response .= '<table><thead><th>Name</th><th>Values</th></thead><tbody>';
                foreach ($attributes as $attributeName => $attributeValues) {
                    $response .= '<tr><td>' . htmlentities($attributeName) . '</td><td><ul>';
                    foreach ($attributeValues as $attributeValue) {
                        $response .= '<li>' . htmlentities($attributeValue) . '</li>';
                    }
                    $response .= '</ul></td></tr>';
                }
                $response .= '</tbody></table>';
            } else {
                $response .= "<p>You don't have any attribute</p>";
            }

            $response .= "<p><a href='{$this->spBaseUrl}/saml?slo' >Logout</a></p>";
        } else {
            $response .= "<p><a href='{$this->spBaseUrl}/saml?sso2'>Login and access later to this page</a></p>";

        }
        return new Response($response);
    }
}