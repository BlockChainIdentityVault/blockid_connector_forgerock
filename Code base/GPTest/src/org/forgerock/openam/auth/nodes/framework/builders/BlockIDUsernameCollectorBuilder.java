package org.forgerock.openam.auth.nodes.framework.builders;

import org.forgerock.openam.auth.nodes.BlockIDUsernameCollectorNode;

public class BlockIDUsernameCollectorBuilder extends AbstractNodeBuilder implements BlockIDUsernameCollectorNode.Config {
	 private static final String DEFAULT_DISPLAY_NAME = "BlockID User Name Collector";
	  
	  public BlockIDUsernameCollectorBuilder() {
	    super("BlockID User Name Collector", (Class)BlockIDUsernameCollectorNode.class);
	  }
}
