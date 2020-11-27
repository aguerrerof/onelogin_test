<?php


namespace App\Service;

interface IdentityProvider
{
    function auth();

    function settings();

    function getSSOUrl();

    function getServiceProviderUrl();

    function getConfiguration();

    function setAuth($auth);
}