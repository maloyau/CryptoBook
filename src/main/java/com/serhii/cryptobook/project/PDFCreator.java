package com.serhii.cryptobook.project;

import com.itextpdf.text.pdf.PdfReader;

import java.io.IOException;

public class PDFCreator {

    public static void main(String[] args) {
        PdfReader reader = null;
        try {
            reader = new PdfReader("D:\\bcguide.pdf");
        } catch (IOException e) {
            System.out.println("Не удается открыть файл!");
        }
        if (reader != null) {
            System.out.println(reader.getFileLength());
            System.out.println(reader.getNumberOfPages());
        }
        System.out.println("Pause");
    }
}
