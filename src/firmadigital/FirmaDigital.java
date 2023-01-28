package firmadigital;

import java.security.Signature;
import java.security.SignatureException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

// Biblioteca necesaria para mostrar en ASCII el resultado por pantalla
import static org.apache.commons.codec.binary.Base64.encodeBase64;

 /**
  * Ejemplo de uso de firmas digitales: 
 * (1) Se crea un par RSA y se firma el texto con la clave privada.
 * (2) Se muestra la firma obtenida en BASE64
 * (3) Verifica la firma con la correspondiente clave pública 
 * IMPORTANTE: descargar la biblioteca de commons-codec de Apache, de la URL:
 *  http://commons.apache.org/proper/commons-codec/download_codec.cgi
 * e incluir el fichero commons-codec.jar entre las bibliotecas del proyecto.
 * 
 * @author oscar
 */
public class FirmaDigital {

  public static void main (String[] args) throws Exception {
 
    System.out.println("Generando un par RSA...");
    KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
    generador.initialize(1024);
    KeyPair parClaves = generador.genKeyPair();
    System.out.println("Generando el par de claves.");

    byte[] datos = "Este es el texto que vamos a firmar".getBytes("UTF8");

    // Obtener instancia del objeto Signature e inicializarlo con 
    // la clave privada para firmarlo
    Signature firma = Signature.getInstance("MD5WithRSA");
    firma.initSign(parClaves.getPrivate());

    // Prepara la firma de los datos
    firma.update(datos);

    // Firmar los datos
    byte[] bytesFirma = firma.sign();

    // Mostrar en ASCII
    System.out.println("\nFirma:\n" + 
         new String(encodeBase64(bytesFirma)));

    // Ahora procedemos a verificar la firma. Para ello necesitaremos 
    // reinicializar el objeto Signature con la clave pública. 
    // Esto hace un reset de los datos de la firma con lo que hay que 
    // pasárselos de nuevo para hacer el update.
    firma.initVerify(parClaves.getPublic());

    // Pasar los datos que fueron firmados
    firma.update(datos);

    // Verificar
    boolean verificado = false;
    try {
      verificado = firma.verify(bytesFirma);
    } catch (SignatureException se) {
	  verificado = false;
    }

    if (verificado) {
      System.out.println("\nFirma verificada.");
    } else {
      System.out.println("\nFirma incorrecta.");
    }
  }
}

