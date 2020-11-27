<?php

namespace App\Controller\SAML;

use App\Service\Adapters\OneLoginAdapter;
use Exception;
use OneLogin\Saml2\Utils;
use OneLogin\Saml2\ValidationError;
use Symfony\Component\HttpFoundation\Response;
use OneLogin\Saml2\Error;
use Symfony\Component\Routing\Annotation\Route;

class IndexController
{
    /**
     * @var OneLoginAdapter
     */
    private $identityProviderService;

    /**
     * IndexController constructor.
     * @param OneLoginAdapter $identityProviderService
     */
    public function __construct(OneLoginAdapter $identityProviderService)
    {
        //Not a good practice, I know
        $this->identityProviderService = $identityProviderService;
    }

    /**
     * @Route("/saml", name="saml_auth")
     * @throws Error|\Doctrine\DBAL\Exception
     */
    public function saml()
    {
        if (!isset($_SESSION)) {
            session_start();
        }
        try {
            $auth = $this->identityProviderService->auth();
        } catch (Exception $e) {
            return new Response($e->getMessage(), Response::HTTP_CONFLICT);
        }
        if (isset($_GET['sso'])) {
            //$auth->login();

            # If AuthNRequest ID need to be saved in order to later validate it, do instead
            $this->identityProviderService->setAuth($auth);
            $ssoBuiltUrl = $this->identityProviderService->getSSOUrl();
            $_SESSION['AuthNRequestID'] = $auth->getLastRequestID();
            header('Pragma: no-cache');
            header('Cache-Control: no-cache, must-revalidate');
            header('Location: ' . $ssoBuiltUrl);
            exit();

        } else if (isset($_GET['sso2'])) {
            $configuration = $this->identityProviderService->getConfiguration();
            $returnTo = $configuration["sp"]["entityId"];
            try {
                $auth->login($returnTo);
            } catch (Error $e) {
                return new Response($e->getMessage(), Response::HTTP_CONFLICT);
            }
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

            try {
                $auth->processResponse($requestID);
            } catch (Error $e) {
                return new Response($e->getMessage(), Response::HTTP_CONFLICT);
            } catch (ValidationError $e) {
                return new Response($e->getMessage(), Response::HTTP_CONFLICT);
            }

            $errors = $auth->getErrors();
            if (!empty($errors)) {
                $errors = implode(', ', $errors);
                return new Response($errors, Response::HTTP_CONFLICT);
            }

            if (!$auth->isAuthenticated()) {
                return new Response("<p>Not authenticated</p>", Response::HTTP_UNAUTHORIZED);
            }

            $_SESSION['samlUserdata'] = $auth->getAttributes();
            $_SESSION['samlNameId'] = $auth->getNameId();
            $_SESSION['samlNameIdFormat'] = $auth->getNameIdFormat();
            $_SESSION['samlNameIdNameQualifier'] = $auth->getNameIdNameQualifier();
            $_SESSION['samlNameIdSPNameQualifier'] = $auth->getNameIdSPNameQualifier();
            $_SESSION['samlSessionIndex'] = $auth->getSessionIndex();
            unset($_SESSION['AuthNRequestID']);
            if (isset($_POST['RelayState']) && Utils::getSelfURL() != $_POST['RelayState']) {
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
                return new Response("<p>Sucessfully logged out</p>", Response::HTTP_OK);

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