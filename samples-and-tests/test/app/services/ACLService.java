package services;

import security.annotation.Access;
import security.annotation.Access.AccessType;

import model.Document;
import model.User;

public class ACLService {
    
    public void save(@Access({AccessType.WRITE, AccessType.READ}) User user) {
        System.out.println("Saving changes in user");
    }
    
    
    public void delete(@Access(value = { AccessType.DELETE }, type = User.class) Long userid) {
        System.out.println("Deleting user");
    }
    
    public void addDocument(@Access(value = { AccessType.WRITE }, type = Document.class) User user, Document document) {
        System.out.println("adding document where user is author");
    }

}
