<?php
/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware.Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Psen\OAuthBundle\OAuth\ResourceOwner;

use HWI\Bundle\OAuthBundle\OAuth\ResourceOwner\GenericOAuth2ResourceOwner;
use Symfony\Component\HttpFoundation\Request;

/**
 * VkontakteResourceOwner
 *
 * @author Sergey Poulikov <sergey@poulikov.ru>
 */
class MailruResourceOwner extends GenericOAuth2ResourceOwner
{
    /**
     * {@inheritDoc}
     */
    protected $options = array(
        'authorization_url'   => 'https://connect.mail.ru/oauth/authorize',
        'access_token_url'    => 'https://connect.mail.ru/oauth/token',
        'infos_url'           => 'http://www.appsmail.ru/platform/api',
        'scope'               => '',
        'user_response_class' => '\HWI\Bundle\OAuthBundle\OAuth\Response\AdvancedPathUserResponse',
    );

    /**
     * {@inheritDoc}
     */
    protected $paths = array(
        'identifier' => 'uid',
        'nickname'   => 'nick',
        'realname'   => 'nick',
    );

    /**
     * Sign request
     */
    protected function signRequest($requestParams, $secretKey)
    {
        ksort($requestParams);
        $params = '';
        foreach ($requestParams as $key => $value) {
            $params .= "$key=$value";
        }

        return md5($params . $secretKey);
    }

    /**
     * {@inheritDoc}
     */
    public function getAccessToken(Request $request, $redirectUri, array $extraParameters = array())
    {
        $parameters = array_merge($extraParameters, array(
            'code'          => $request->query->get('code'),
            'grant_type'    => 'authorization_code',
            'client_id'     => $this->getOption('client_id'),
            'client_secret' => $this->getOption('client_secret'),
            'redirect_uri'  => $redirectUri,
        ));

        $response = $this->doGetAccessTokenRequest($this->getOption('access_token_url'), $parameters);
        $response = $this->getResponseContent($response);

        if (isset($response['error'])) {
            throw new AuthenticationException(sprintf('OAuth error: "%s"', $response['error']));
        }

        if (is_array($response)) {
            $tmp = each($response);
            $response = json_decode($tmp['key'], true);
        }

        if (!isset($response['access_token'])) {
            throw new AuthenticationException('Not a valid access token.');
        }

        return array($response['access_token'], $response['x_mailru_vid']);
    }

    /**
     * {@inheritDoc}
     */
    public function getUserInformation($accessToken)
    {
        $params = array(
            'app_id'       => $this->getOption('client_id'),
            'method'       => 'users.getInfo',
            'access_token' => $accessToken[0],
            'secure'       => 1,
            'uids'         => $accessToken[1]
        );

        $params['sig'] = $this->signRequest($params, $this->getOption('client_secret'));

        $url = $this->getOption('infos_url');
        $url .= (false !== strpos($url, '?') ? '&' : '?').http_build_query($params);

        $content = $this->doGetUserInformationRequest($url)->getContent();
        $content = substr(substr($content, 1), 0, -1);

        $response = $this->getUserResponse();
        $response->setResponse($content);
        $response->setResourceOwner($this);
        $response->setAccessToken($accessToken);

        return $response;
    }

    protected function paths()
    {
        return array(
            'identifier' => 'uuid',
            'nickname' => 'nick',
            'realname' => 'nick'
        );
    }

    public function configure()
    {
        $this->options['scope'] = str_replace(',', ' ', $this->options['scope']);
    }
}
