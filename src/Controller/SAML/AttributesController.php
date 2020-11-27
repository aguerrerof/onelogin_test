<?php


namespace App\Controller\SAML;


use App\Service\Adapters\OneLoginAdapter;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class AttributesController
{
    /**
     * @var OneLoginAdapter
     */
    private $identityProviderService;

    /**
     * AttributesController constructor.
     * @param OneLoginAdapter $identityProviderService
     */
    public function __construct(OneLoginAdapter $identityProviderService)
    {
        $this->identityProviderService =  $identityProviderService;
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

            $response .= "<p><a href='{$this->identityProviderService->getServiceProviderUrl()}/saml?slo' >Logout</a></p>";
        } else {
            $response .= "<p><a href='{$this->identityProviderService->getServiceProviderUrl()}/saml?sso2'>Login and access later to this page</a></p>";

        }
        return new Response($response);
    }
}