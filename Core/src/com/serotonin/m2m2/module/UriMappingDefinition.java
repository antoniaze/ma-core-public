package com.serotonin.m2m2.module;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.serotonin.m2m2.vo.User;
import com.serotonin.m2m2.vo.permission.PermissionException;
import com.serotonin.m2m2.web.mvc.UrlHandler;

abstract public class UriMappingDefinition extends ModuleElementDefinition {
    private static final Log LOG = LogFactory.getLog(UriMappingDefinition.class);
    
    public enum Permission {
        ANONYMOUS, //Anyone
        USER, //Mango User
        DATA_SOURCE, //Can edit data sources
        ADMINISTRATOR, //Can do all
        CUSTOM; //Module defined special access
    }

    /**
     * The user authority required to access the handler.
     * 
     * @return the required authority level.
     */
    @Deprecated
    public Permission getPermission() {
        return null;
    }
    
    public String[] requirePermissions() {
        Permission perm = getPermission();
        if (perm == null)
            return new String[] {"IS_AUTHENTICATED_REMEMBERED"};
        switch(perm) {
        case CUSTOM:
            LOG.warn(this.getClass() + " requested CUSTOM permission, defaulting to ROLE_ADMIN");
        case ADMINISTRATOR:
            return new String[] {"ROLE_ADMIN"};
        case ANONYMOUS:
            return new String[] {"IS_AUTHENTICATED_ANONYMOUSLY"};
        case DATA_SOURCE:
            return new String[] {"DATA_SOURCE"};
        case USER:
        default:
            return new String[] {"IS_AUTHENTICATED_REMEMBERED"};
        }
    }

    /**
     * The URI path to which this controller responds. Required.
     * 
     * @return the controller's URI path.
     */
    abstract public String getPath();

    /**
     * An instance of the handler for the URL. Called once upon startup, so the instance must be reusable and thread
     * safe. If null, a default handler will be created which forwards to the the JSP path.
     * 
     * TODO should reference a UriHandler instead
     * 
     * @return an instance of the URL handler
     */
    abstract public UrlHandler getHandler();

    /**
     * The path to the JSP file that renders the page at this URI. The path is relative to the module directory.
     * Required if the UrlHandler is null.
     * 
     * @return the path to the JSP file.
     */
    abstract public String getJspPath();

	/**
	 * Override as needed when using CUSTOM permissions type
	 * 
	 * @param user
	 * @return
	 */
    @Deprecated
	public boolean hasCustomPermission(User user) throws PermissionException{
		return false;
	}
}
