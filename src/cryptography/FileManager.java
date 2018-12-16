package cryptography;

import java.io.FileInputStream;
import java.io.FileOutputStream;
////////////////////////////////////////////////////////////////////////////////////////////////////
public class FileManager
{
    //------------------------------------------------------ Writing to and reading bytes from files
    public byte[] readBytesFromFile(String filename)
            throws Exception
    {
        FileInputStream fileInputStream = new FileInputStream(filename);
        byte[] inputBytes = new byte[fileInputStream.available()];

        fileInputStream.read(inputBytes);
        fileInputStream.close();

        return inputBytes;
    }
    public void writeBytesToFile(byte outputBytes[], String filename)
            throws Exception
    {
        FileOutputStream fileOutputStream = new FileOutputStream(filename);

        fileOutputStream.write(outputBytes);
        fileOutputStream.close();
    }
}
////////////////////////////////////////////////////////////////////////////////////////////////////