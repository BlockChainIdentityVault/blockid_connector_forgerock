package org.forgerock.openam.auth.nodes;

import org.forgerock.openam.auth.node.api.AbstractNodeAmPlugin;


import java.util.Collections;
import java.util.Map;
import org.forgerock.openam.auth.node.api.Node;


public class BlockIDUsernameCollectorNodePlugin extends AbstractNodeAmPlugin { 
	private static String currentVersion = "1.0.0";
	
	 @Override
	  protected Map<String, Iterable<? extends Class<? extends Node>>>
	  getNodesByVersion() {
	    return Collections.singletonMap("1.0.0", Collections.singletonList(BlockIDUsernameCollectorNode.class));
	  }

	  @Override
	  public String getPluginVersion() {
	    return BlockIDUsernameCollectorNodePlugin.currentVersion;
	  }
}
