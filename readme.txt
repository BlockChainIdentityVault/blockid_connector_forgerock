auth-nodes-7.1.0.jar - It contains packaged BlockID customized zero login collector node. 
Forgerock connector deployment.docx - contains deployment document for the artefacts
lib - contains library files required for BlockID to be deployed in Forgerock
Code base- Eclipse java project for custom Forgerock node, customized node, blockid.properties file and helper files mentioned in deployment document.
JavaSDK - If JavaSDK to be used for encryption/decryption it can be deployed on tomcat server. blockid.js needs to be referred from same. In case of php sdk, package provided by engineering team to be used


Forgerock Environment Details:
URL: https://forgerock.blockid.co
Forgerock admin: amadmin/1Kosmos123$
AWS machine IP address:  18.224.67.227   (obtain key file to connect to this machine from Vik/Rohan)
Forgerock home location: /opt/apache-tomcat-8.5.54/webapps/ROOT/
Forgerock code base: /opt/rohan/am-external
UI customization files: /opt/rohan/am-external/openam-ui
Login page customization file: 
/opt/rohan/am-external/openam-ui/openam-ui-user/src/resources/themes/default/templates/openam/authn/DataStore1.html
/opt/apache-tomcat-8.5.54/webapps/ROOT/XUI/index.html

