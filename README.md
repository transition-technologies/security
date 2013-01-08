Security
=========

Playframework 1.2 module to handle annotation and tag based security checks everywhere, not only in controllers.

Security Module was meant to be the extension of Deadbolt Module but while developing the Security Module we decided 
that it should be seperate implementation - added logic is independent from Deadbolt.

Usage
-----
To use security plugin simply add it to your application (see [Installation](#Installation))
and use security annotations for method parameters wherever you like (not only in controllers), ex:
```@Access @AnyRole @RoleRequired @Unsecured```

* @RoleRequired - checks user is in one of specified roles

```
	@RoleRequired({"ADMIN"})
    public void accessForAdminOnly() {
    }
```

* @AnyRole - checks user is logged in 

```
	@AnyRole
    public void securedMethod() {
    }
```	

* @Unsecured - marks method that is not secured 

```
@RoleRequired({"ADMIN"})
public class RestrictedService {

    @Unsecured
    public void doSimpleChange() {
    } 
}
```	

* @Access - checks user has access for annotated AclManaged object 

```
public void save(@Access({AccessType.WRITE, AccessType.READ}) Document document) {
}
```	

Moreover you can use security tags to secure parts of your play templates.

* roleRequired - content within the tag is shown to users in one of specified roles

```
#{security.roleRequired roles: ['ADMIN', 'USER']}
This is shared content for admin and user
#{/security.roleRequired}
```

* anyRole - content within the tag is shown to logged in users 

```
#{security.anyRole}
This is content for logged user
#{/security.anyRole}
```

* access - content within the tag is shown to user which has access to given AclManaged object

```
#{security.access contextObject: _document, accessTypes: [security.annotation.Access.AccessType.WRITE]}
Link to add document
#{/security.access}
```


Installation
------------
Add repository and dependency to your dependencies.yml:
  
    require:
		- play
		- pl.com.tt.play.modules -> security 1.1.0
	repositories:
		- pl.com.tt.play.modules:
			type:       http
			artifact:   http://cloud.github.com/downloads/transition-technologies/[module]/[module]-[revision].zip
			descriptor: http://cloud.github.com/downloads/transition-technologies/[module]/[module]-[revision].yml
			contains:
				- pl.com.tt.play.modules -> *
