<?php declare (strict_types=1);

namespace Sabre\DAV;

class CorePluginTest extends \PHPUnit_Framework_TestCase {

    function testGetInfo() {

        $corePlugin = new CorePlugin();
        $this->assertEquals('core', $corePlugin->getPluginInfo()['name']);

    }

}
