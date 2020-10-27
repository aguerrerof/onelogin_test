<?php

namespace App\Controller\SAML;

use Exception;
use Symfony\Component\HttpFoundation\Response;
use OneLogin\Saml2\Error as OneLogin_Saml2_Error;
use OneLogin\Saml2\Settings as OneLogin_Saml2_Settings;
use OneLogin\Saml2\Auth as OneLogin_Saml2_Auth;
use Symfony\Component\Routing\Annotation\Route;

class IndexController
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
     * IndexController constructor.
     * @param string $baseUrl
     * @param string $nameIdFormat
     * @param string $idpEntityId
     * @param string $ssoUrl
     * @param string $slsUrl
     * @param string $idpCert
     */
    public function __construct(string $baseUrl, string $nameIdFormat, string $idpEntityId, string $ssoUrl, string $slsUrl, string $idpCert)
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

    /**
     * @Route("/saml", name="saml_auth")
     */
    public function saml()
    {
        if (!isset($_SESSION)) {
            session_start();
        } else {
            session_destroy();
            session_start();
        }
        try {
            $auth = new OneLogin_Saml2_Auth($this->configuration_bundle);
        } catch (Exception $e) {
            return new Response($e->getMessage());
        }

        if (isset($_GET['sso'])) {
            //$auth->login();

            # If AuthNRequest ID need to be saved in order to later validate it, do instead
            $ssoBuiltUrl = $auth->login(null, array(), false, false, true);
            $_SESSION['AuthNRequestID'] = $auth->getLastRequestID();
            header('Pragma: no-cache');
            header('Cache-Control: no-cache, must-revalidate');
            header('Location: ' . $ssoBuiltUrl);
            exit();

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
                $errors = implode(', ', $errors);
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
}