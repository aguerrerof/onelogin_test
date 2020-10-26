<?php

namespace App\Controller;

use Exception;
use OneLogin_Saml2_Utils;
use Symfony\Component\HttpFoundation\Response;
use OneLogin_Saml2_Auth;
use OneLogin_Saml2_Error;
use OneLogin_Saml2_Settings;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Annotation\Route;

class AuthController
{
    /**
     * @var array[]
     */
    private $configuration_bundle;
    /**
     * @var string
     */
    private $spBaseUrl;

    /**
     * AuthController constructor.
     */
    public function __construct()
    {
        //Not a good practice, I know
        $this->spBaseUrl = $_ENV['BASE_URL'];
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
                'entityId' => 'https://app.onelogin.com/saml/metadata/de21a386-47b2-4860-a12a-0d7d45db2746',
                'singleSignOnService' => array(
                    'url' => 'https://teamq-dev.onelogin.com/trust/saml2/http-post/sso/de21a386-47b2-4860-a12a-0d7d45db2746',
                ),
                'singleLogoutService' => array(
                    'url' => 'https://teamq-dev.onelogin.com/trust/saml2/http-redirect/slo/1290930',
                ),
                'x509cert' => '0E:27:28:9D:4A:85:BA:E3:8F:2D:3B:78:59:35:E0:12:9E:E8:28:D6',
            ),
        ];
    }

    /**
     * @Route("/saml", name="saml_auth")
     */
    public function index()
    {
        if (!isset($_SESSION)) {
            session_start();
        }
        try {
            $auth = new OneLogin_Saml2_Auth($this->configuration_bundle);
        } catch (\OneLogin_Saml2_Error $e) {
            return new Response($e->getMessage());
        }

        if (isset($_GET['sso'])) {
            $auth->login();

            # If AuthNRequest ID need to be saved in order to later validate it, do instead
            # $ssoBuiltUrl = $auth->login(null, array(), false, false, true);
            # $_SESSION['AuthNRequestID'] = $auth->getLastRequestID();
            # header('Pragma: no-cache');
            # header('Cache-Control: no-cache, must-revalidate');
            # header('Location: ' . $ssoBuiltUrl);
            # exit();

        } else if (isset($_GET['sso2'])) {
            $returnTo = $this->spBaseUrl . '/attributes';
            $auth->login($returnTo);
        } else if (isset($_GET['slo'])) {
            $returnTo = null;
            $parameters = array();
            $nameId = null;
            $sessionIndex = null;
            $nameIdFormat = null;

            if (isset($_SESSION['samlNameId'])) {
                $nameId = $_SESSION['samlNameId'];
            }
            if (isset($_SESSION['samlNameIdFormat'])) {
                $nameIdFormat = $_SESSION['samlNameIdFormat'];
            }
            if (isset($_SESSION['samlNameIdNameQualifier'])) {
                $nameIdNameQualifier = $_SESSION['samlNameIdNameQualifier'];
            }
            if (isset($_SESSION['samlNameIdSPNameQualifier'])) {
                $nameIdSPNameQualifier = $_SESSION['samlNameIdSPNameQualifier'];
            }
            if (isset($_SESSION['samlSessionIndex'])) {
                $sessionIndex = $_SESSION['samlSessionIndex'];
            }

            $auth->logout($returnTo, $parameters, $nameId, $sessionIndex, false, $nameIdFormat, $nameIdNameQualifier, $nameIdSPNameQualifier);

            # If LogoutRequest ID need to be saved in order to later validate it, do instead
            # $sloBuiltUrl = $auth->logout(null, $paramters, $nameId, $sessionIndex, true);
            # $_SESSION['LogoutRequestID'] = $auth->getLastRequestID();
            # header('Pragma: no-cache');
            # header('Cache-Control: no-cache, must-revalidate');
            # header('Location: ' . $sloBuiltUrl);
            # exit();

        } else if (isset($_GET['acs'])) {
            if (isset($_SESSION) && isset($_SESSION['AuthNRequestID'])) {
                $requestID = $_SESSION['AuthNRequestID'];
            } else {
                $requestID = null;
            }

            $auth->processResponse($requestID);

            $errors = $auth->getErrors();

            if (!empty($errors)) {
                $errors =  implode(', ', $errors);
                return new Response($errors);
            }

            if (!$auth->isAuthenticated()) {
                return new Response("<p>Not authenticated</p>");
            }

            $_SESSION['samlUserdata'] = $auth->getAttributes();
            $_SESSION['samlNameId'] = $auth->getNameId();
            $_SESSION['samlNameIdFormat'] = $auth->getNameIdFormat();
            $_SESSION['samlNameIdNameQualifier'] = $auth->getNameIdNameQualifier();
            $_SESSION['samlNameIdSPNameQualifier'] = $auth->getNameIdSPNameQualifier();
            $_SESSION['samlSessionIndex'] = $auth->getSessionIndex();
            unset($_SESSION['AuthNRequestID']);
            if (isset($_POST['RelayState']) && OneLogin_Saml2_Utils::getSelfURL() != $_POST['RelayState']) {
                $auth->redirectTo($_POST['RelayState']);
            }
        } else if (isset($_GET['sls'])) {
            if (isset($_SESSION) && isset($_SESSION['LogoutRequestID'])) {
                $requestID = $_SESSION['LogoutRequestID'];
            } else {
                $requestID = null;
            }

            $auth->processSLO(false, $requestID);
            $errors = $auth->getErrors();
            if (empty($errors)) {
                return new Response("<p>Sucessfully logged out</p>");

            } else {
                return new Response(implode(', ', $errors));
            }
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
                return new Response("<p>You don't have any attribute</p>");

            }
            $response .= '<p><a href="?slo" >Logout</a></p>';
        } else {
            $response .= '<p><a href="?sso" >Login</a></p>';
            $response .= '<p><a href="?sso2" >Login and access to attrs.php page</a></p>';
        }
        return new Response($response, Response::HTTP_OK);
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

    /**
     * @Route("/attributes", name="attributes")
     */
    public function attributes()
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