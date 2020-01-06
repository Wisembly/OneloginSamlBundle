<?php

namespace Hslavich\OneloginSamlBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Exception\ServiceNotFoundException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\HttpFoundation\Request;

class SamlController extends AbstractController
{
    /**
     * @param Request $request
     * @param string  $idp
     */
    public function loginAction(Request $request, string $idp)
    {
        $session = $request->getSession();
        $authErrorKey = Security::AUTHENTICATION_ERROR;

        if ($request->attributes->has($authErrorKey)) {
            $error = $request->attributes->get($authErrorKey);
        } elseif (null !== $session && $session->has($authErrorKey)) {
            $error = $session->get($authErrorKey);
            $session->remove($authErrorKey);
        } else {
            $error = null;
        }

        if ($error) {
            throw new \RuntimeException($error->getMessage());
        }

        try {
            $this->get('onelogin_auth.' . $idp)->login();
        } catch (ServiceNotFoundException $e) {
            throw new \Exception(sprintf("Unknown IDP '%s'", $idp));
        }
    }

    /**
     * @param string $idp
     * @return Response
     */
    public function metadataAction(string $idp)
    {
        try {
            $auth = $this->get('onelogin_auth.' . $idp);
        } catch (ServiceNotFoundException $e) {
            throw new \Exception(sprintf("Unknown IDP '%s'", $idp));
        }

        $metadata = $auth->getSettings()->getSPMetadata();

        $response = new Response($metadata);
        $response->headers->set('Content-Type', 'xml');

        return $response;
    }

    public function assertionConsumerServiceAction()
    {
        throw new \RuntimeException('You must configure the check path to be handled by the firewall.');
    }

    public function singleLogoutServiceAction()
    {
        throw new \RuntimeException('You must activate the logout in your security firewall configuration.');
    }
}
