<?php

namespace Sabre\DAV\Sharing;

use Sabre\DAV\Exception\BadRequest;
use Sabre\DAV\Exception\Forbidden;
use Sabre\DAV\INode;
use Sabre\DAV\PropFind;
use Sabre\DAV\Server;
use Sabre\DAV\ServerPlugin;
use Sabre\DAV\Xml\Property;
use Sabre\HTTP\RequestInterface;
use Sabre\HTTP\ResponseInterface;

/**
 * This plugin implements HTTP requests and properties related to:
 *
 * draft-pot-webdav-resource-sharing-02
 *
 * This specification allows people to share webdav resources with others.
 *
 * @copyright Copyright (C) 2007-2015 fruux GmbH. (https://fruux.com/)
 * @author Evert Pot (http://evertpot.com/)
 * @license http://sabre.io/license/ Modified BSD License
 */
class Plugin extends ServerPlugin {

    const ACCESS_NOTSHARED = 0;
    const ACCESS_SHAREDOWNER = 1;
    const ACCESS_READ = 2;
    const ACCESS_READWRITE = 3;
    const ACCESS_NOACCESS = 4;

    const INVITE_NORESPONSE = 1;
    const INVITE_ACCEPTED = 2;
    const INVITE_DECLINED = 3;
    const INVITE_INVALID = 4;

    /**
     * Reference to SabreDAV server object.
     *
     * @var Sabre\DAV\Server
     */
    protected $server;

    /**
     * This method should return a list of server-features.
     *
     * This is for example 'versioning' and is added to the DAV: header
     * in an OPTIONS response.
     *
     * @return array
     */
    function getFeatures() {

        return ['resource-sharing'];

    }

    /**
     * Returns a plugin name.
     *
     * Using this name other plugins will be able to access other plugins
     * using \Sabre\DAV\Server::getPlugin
     *
     * @return string
     */
    function getPluginName() {

        return 'sharing';

    }

    /**
     * This initializes the plugin.
     *
     * This function is called by Sabre\DAV\Server, after
     * addPlugin is called.
     *
     * This method should set up the required event subscriptions.
     *
     * @param Server $server
     * @return void
     */
    function initialize(Server $server) {

        $this->server = $server;

        $server->xml->elementMap['{DAV:}share-resource'] = 'Sabre\\DAV\\Xml\\Request\\ShareResource';

        array_push(
            $server->protectedProperties,
            '{DAV:}share-mode'
        );

        $server->on('method:POST',  [$this, 'httpPost']);
        $server->on('propFind',     [$this, 'propFind']);

    }

    /**
     * Updates the list of sharees on a shared resource.
     *
     * The sharees  array is a list of people that are to be added modified
     * or removed in the list of shares.
     *
     * @param string $path
     * @param Sharee[] $sharees
     * @return void
     */
    function shareResource($path, array $sharees) {

        try {
            $node = $this->server->tree->getNodeForPath($path);
        } catch (DAV\Exception\NotFound $e) {
            // If the target node is not found, we stop executing.
            return;
        }

        if (!$node instanceof ISharedNode) {

            throw new Forbidden('Sharing is not allowed on this node');

        }

        // Getting ACL info
        $acl = $this->server->getPlugin('acl');

        // If there's no ACL support, we allow everything
        if ($acl) {
            $acl->checkPrivileges($path, '{DAV:}share');
        }

        $node->updateInvites($sharees);

    }

    /**
     * This event is triggered when properties are requested for nodes.
     *
     * This allows us to inject any sharings-specific properties.
     *
     * @param PropFind $propFind
     * @param INode $node
     * @return void
     */
    function propFind(PropFind $propFind, INode $node) {

        if ($node instanceof ISharedNode) {

            $propFind->handle('{DAV:}share-access', function() use ($node) {

                return new Property\ShareAccess($node->getShareAccess());

            });
            $propFind->handle('{DAV:}invite', function() use ($node) {

                return new Property\Invites($node->getInvites());

            });
            $propFind->handle('{DAV:}share-resource-uri', function() use ($node) {

                return new Property\Href($node->getShareResourceUri());

            });

        }

    }

    /**
     * We intercept this to handle POST requests on shared resources
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @return null|bool
     */
    function httpPost(RequestInterface $request, ResponseInterface $response) {

        $path = $request->getPath();
        $contentType = $request->getHeader('Content-Type');

        // We're only interested in the davsharing content type.
        if (strpos($contentType, 'application/davsharing+xml') === false) {
            return;
        }

        $message = $this->server->xml->parse(
            $request->getBody(),
            $request->getUrl(),
            $documentType
        );

        switch ($documentType) {

            case '{DAV:}share-resource':

                $this->shareResource($path, $message->sharees);
                $response->setStatus(200);
                // Adding this because sending a response body may cause issues,
                // and I wanted some type of indicator the response was handled.
                $response->setHeader('X-Sabre-Status', 'everything-went-well');

                // Breaking the event chain
                return false;

            default :
                throw new BadRequest('Unexpected document type: ' . $documentType . ' for this Content-Type');

        }

    }

    /**
     * Returns a bunch of meta-data about the plugin.
     *
     * Providing this information is optional, and is mainly displayed by the
     * Browser plugin.
     *
     * The description key in the returned array may contain html and will not
     * be sanitized.
     *
     * @return array
     */
    function getPluginInfo() {

        return [
            'name'        => $this->getPluginName(),
            'description' => 'This plugin implements WebDAV resource sharing',
            'link'        => 'https://github.com/evert/webdav-sharing'
        ];

    }

}
