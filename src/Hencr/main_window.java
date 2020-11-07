package Hencr;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.Random;
import java.util.Vector;

public class main_window {

    private static final String FILENAME =  "encryption key location";
    private JFrame main_view_frame;
    private JFrame encrypted_table, decrypted_table;
    private JLabel heading_label;
    private JPanel view_layout;
    static Paillier paillier;
    private static String ip_db,database_name, password_db, username_db;
    static aes aes_enc;
    static file file_obj;
    static BigInteger key;

    String enc_lpassword = "";
    String enc_lusername = "";

    public main_window(){
        prepareGUI();
    }

    public static void main(String[] args){
        file_obj=new file();
        paillier = new Paillier();

        if(file_obj.check(FILENAME)){
            BigInteger[] key_value_array = file_obj.getKey(FILENAME);
            paillier.KeyGeneration(512, 62,key_value_array[0],key_value_array[1]);
            key = key_value_array[2];
        }

        else {
            key = new BigInteger(512, new Random());
            paillier.KeyGeneration(512, 62);
            BigInteger[] temp;
            temp = paillier.getPQ();
            temp[2] = new BigInteger(""+key);
            temp[3] = new BigInteger("" + 100 +  (int)(Math.random()*(10000-100+1)));
            file_obj.fileWrite(temp,FILENAME);
        }

        aes_enc = new aes();
        ip_db = "192.168.43.205";
        database_name = "datbase";
        password_db = "test";
        username_db = "test";

        String ena=aes_enc.encrypt("cred_table");
        System.out.println("BANK" + ena);

        main_window main_window = new main_window();
        main_window.showTextFieldDemo();
    }

    public static DefaultTableModel enc_table_view(ResultSet rs)
            throws SQLException {

        ResultSetMetaData metaData = rs.getMetaData();
        rs.beforeFirst();

        Vector<String> name_cols = new Vector<>();
        int columnCount = metaData.getColumnCount();
        for (int column = 1; column <= columnCount; column++) {
            name_cols.add(metaData.getColumnName(column));
        }

        Vector<Vector<Object>> data = new Vector<>();
        while (rs.next()) {
            Vector<Object> vector = new Vector<>();
            for (int col_index = 1; col_index <= columnCount; col_index++) {
                vector.add(rs.getObject(col_index));
            }
            data.add(vector);
        }

        return new DefaultTableModel(data, name_cols);
    }

    public static DefaultTableModel dec_table_view(ResultSet rs)
            throws SQLException {

        ResultSetMetaData metaData = rs.getMetaData();
        rs.beforeFirst();

        Vector<String> name_of_cols = new Vector<String>();
        int number_of_cols = metaData.getColumnCount();
        for (int column = 1; column <= number_of_cols; column++) {
            name_of_cols.add(aes_enc.decrypt(metaData.getColumnName(column)));
        }

        Vector<Vector<Object>> data = new Vector<>();
        while (rs.next()) {
            Vector<Object> vector = new Vector<>();
            for (int col_index = 1; col_index <= number_of_cols; col_index++) {
                if(col_index==2)
                    vector.add(paillier.DecrpyStr(new BigInteger(rs.getString(col_index))));
                else
                    vector.add(paillier.Decryption(new BigInteger(rs.getString(col_index))));
            }
            data.add(vector);
        }

        System.out.println("Values : ");
        for (Vector<Object> array : data) {
            for (Object obj : array) {
                System.out.println(obj);
            }
        }

        return new DefaultTableModel(data, name_of_cols);

    }

    public void create_table(String table_name,String col1,String col2, String col3) {
        try{
            Class.forName("net.sourceforge.jtds.jdbc.Driver");
            Connection con=DriverManager.getConnection("jdbc:jtds:sqlserver://"+ip_db+":1433/"+database_name,username_db,password_db);
        Statement st=con.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_READ_ONLY);

        String table_name_enc=aes_enc.encrypt(table_name + enc_lusername);
        String col1_enc=aes_enc.encrypt(col1);
        String col2_enc=aes_enc.encrypt(col2);
        String col3_enc=aes_enc.encrypt(col3);

        System.out.println("a="+table_name_enc+"\nb="+col1_enc+"\nc="+col2_enc+"\nd="+col3_enc+"\n");
        String up="CREATE TABLE ["+table_name_enc+"] (["+col1_enc+"] VARCHAR(310),["+col2_enc+"] VARCHAR(310), ["+col3_enc+"] VARCHAR(310));";
        System.out.println(up);
        st.execute("CREATE TABLE ["+table_name_enc+"] (["+col1_enc+"] VARCHAR(310),["+col2_enc+"] VARCHAR(310),["+col3_enc+"] VARCHAR(310));");
        ResultSet rs=st.executeQuery("SELECT * FROM "+table_name_enc+";");

        encrypted_table=new JFrame();
        encrypted_table.setSize(640,220);
        encrypted_table.setLocation(460,0);
        JTable t1=new JTable(enc_table_view(rs));
        JScrollPane sp = new JScrollPane(t1);
        sp.setBounds(460,10,640,210);
        encrypted_table.add(sp);
        encrypted_table.setVisible(true);

        decrypted_table=new JFrame();
        decrypted_table.setSize(640,220);
        decrypted_table.setLocation(460,230);
        JTable t2=new JTable(dec_table_view(rs));
        JScrollPane sp1 = new JScrollPane(t2);
        sp.setBounds(460,10,640,210);
        decrypted_table.add(sp1);
        decrypted_table.setVisible(true);

        con.close();
    }
	  		catch(Exception e)
    {
        System.out.println("Connection Error" + e);
    }

    }

    public void insert_into_table(String val1,String val2,String val3,String table_name){
        try{
            Class.forName("net.sourceforge.jtds.jdbc.Driver");
            Connection con=DriverManager.getConnection("jdbc:jtds:sqlserver://"+ip_db+":1433/"+database_name,username_db,password_db);
            Statement st=con.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_READ_ONLY);

            BigInteger a1=new BigInteger(val1);
            BigInteger val1_enc=paillier.Encryption(a1,key);
            BigInteger val2_enc=paillier.EncrypStr(val2,key);
            BigInteger c1=new BigInteger(val3);
            BigInteger val3_enc=paillier.Encryption(c1,key);
            String table_name_enc=aes_enc.encrypt(table_name + enc_lusername);

            st.executeUpdate("INSERT INTO ["+table_name_enc+"] VALUES('"+val1_enc+"','"+val2_enc+"','"+val3_enc+"')");
            System.out.println(val1_enc+" "+val2_enc+" "+val3_enc );

            st.executeQuery("SELECT * FROM [" + table_name_enc + "]");

            ResultSet rs = st.getResultSet();
            encrypted_table=new JFrame();
            encrypted_table.setSize(640,220);
            encrypted_table.setLocation(460,0);
            JTable t1=new JTable(enc_table_view(rs));
            JScrollPane sp = new JScrollPane(t1);
            sp.setBounds(460,10,640,210);
            encrypted_table.add(sp);
            encrypted_table.setVisible(true);
            decrypted_table=new JFrame();
            decrypted_table.setSize(640,220);
            decrypted_table.setLocation(460,230);
            JTable t2=new JTable(dec_table_view(rs));
            JScrollPane sp1 = new JScrollPane(t2);
            sp.setBounds(460,10,640,210);
            decrypted_table.add(sp1);
            decrypted_table.setVisible(true);

            con.close();

        }catch(Exception e)
        {
            System.out.println("Connection Error" + e);
        }
    }

    public void display_from_table(String table_name)
    {
        try{
            Class.forName("net.sourceforge.jtds.jdbc.Driver");
            Connection con=DriverManager.getConnection("jdbc:jtds:sqlserver://"+ip_db+":1433/"+database_name,username_db,password_db);
            Statement st=con.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_READ_ONLY);
            String table_name_enc=aes_enc.encrypt(table_name + enc_lusername);
            st.executeQuery("SELECT * FROM ["+table_name_enc+"]");

            ResultSet rs = st.getResultSet();
            encrypted_table=new JFrame();
            encrypted_table.setSize(640,220);
            encrypted_table.setLocation(460,0);
            JTable t1=new JTable(enc_table_view(rs));
            JScrollPane sp = new JScrollPane(t1);
            sp.setBounds(460,10,640,210);
            encrypted_table.add(sp);
            encrypted_table.setVisible(true);
            decrypted_table=new JFrame();
            decrypted_table.setSize(640,220);
            decrypted_table.setLocation(460,230);
            JTable t2=new JTable(dec_table_view(rs));
            JScrollPane sp1 = new JScrollPane(t2);
            sp.setBounds(460,10,640,210);
            decrypted_table.add(sp1);
            decrypted_table.setVisible(true);
            con.close();

        }catch(Exception e)
        {
            System.out.println("Connection Error" + e);
        }
    }

    public static boolean isInteger(String s) {
        try {
            Integer.parseInt(s);
        } catch(NumberFormatException | NullPointerException e) {
            return false;
        }
        return true;
    }

    private void prepareGUI(){
        main_view_frame = new JFrame("Save and Secure");
        main_view_frame.setSize(460,440);
        main_view_frame.setLayout(new GridLayout(11, 1));
        main_view_frame.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent windowEvent){
                System.exit(0);
            }
        });

        heading_label = new JLabel("", JLabel.CENTER);

        view_layout = new JPanel();
        view_layout.setLayout(new FlowLayout());

        main_view_frame.add(heading_label);
        main_view_frame.setVisible(true);
    }

    private void showTextFieldDemo(){

        heading_label.setText("Enter Credentials");
        heading_label.setFont(new Font("Montserrat", Font.BOLD, 20));

        JLabel dblabel=new JLabel("Database Name:");
        dblabel.setFont(new Font("Montserrat", Font.PLAIN, 14));
        final JTextField dbname=new JTextField(8);

        JLabel userlabel=new JLabel("User Name:");
        userlabel.setFont(new Font("Montserrat", Font.PLAIN, 14));
        final JTextField username=new JTextField(8);

        JLabel passlabel=new JLabel("Database Password:");
        passlabel.setFont(new Font("Montserrat", Font.PLAIN, 14));
        final JPasswordField pass=new JPasswordField(8);

        JLabel ip=new JLabel("IP: ",JLabel.CENTER);
        ip.setFont(new Font("Montserrat", Font.PLAIN, 14));

        final JTextField serverip=new JTextField(15);

        JLabel  select = new JLabel("SELECT * FROM ");
        select.setFont(new Font("Montserrat", Font.PLAIN, 12));

        final JTextField selectname = new JTextField(8);
        JLabel  li = new JLabel("CREATE TABLE");
        li.setFont(new Font("Montserrat", Font.PLAIN, 12));

        final JTextField nam = new JTextField(6);
        JLabel  li2 = new JLabel("( ", JLabel.CENTER);
        final JTextField attr1 = new JTextField(4);
        JLabel  li3 = new JLabel(", ", JLabel.CENTER);
        final JTextField attr2 = new JTextField(4);

        JLabel  li4 = new JLabel(", ", JLabel.CENTER);
        final JTextField attr3 = new JTextField(4);
        JLabel  li5 = new JLabel(") ", JLabel.CENTER);

        JLabel  la = new JLabel("INSERT INTO ", JLabel.CENTER);
        la.setFont(new Font("Montserrat", Font.PLAIN, 12));

        final JTextField t1 = new JTextField(4);
        JLabel  la1 = new JLabel("VALUES ", JLabel.CENTER);
        la1.setFont(new Font("Montserrat", Font.PLAIN, 12));

        final JTextField val1 = new JTextField(3);
        JLabel  la2 = new JLabel("VALUES ", JLabel.CENTER);
        la2.setFont(new Font("Montserrat", Font.PLAIN, 12));

        final JTextField val2 = new JTextField(3);
        JLabel  la3 = new JLabel("VALUES ", JLabel.CENTER);
        la3.setFont(new Font("Montserrat", Font.PLAIN, 12));

        final JTextField val3 = new JTextField(3);

        JButton convert= new JButton("Process");
        convert.setFont(new Font("Montserrat", Font.BOLD, 14));

        JButton clear = new JButton("Clear");
        clear.setFont(new Font("Montserrat", Font.BOLD, 14));
        clear.setBounds(50, 100, 150, 200);

        JLabel username_login=new JLabel("User Name:");
        username_login.setFont(new Font("Montserrat", Font.PLAIN, 14));
        final JTextField username_login_field=new JTextField(8);

        JLabel pass_login=new JLabel("Password:");
        pass_login.setFont(new Font("Montserrat", Font.PLAIN, 14));
        final JPasswordField pass_login_field=new JPasswordField(8);

        JButton button = new JButton("Login");
        button.setFont(new Font("Montserrat", Font.BOLD, 14));

        button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                String lusername = username_login_field.getText().toString();
                String lpassword = new String(pass_login_field.getPassword());

                //System.out.println("USername : " + lusername + "Password : " + lpassword);
                String pword_hash="";
                try {
                    pword_hash = to_Hexa_String(get_SHA256(lpassword));
                    //System.out.println("Password hash: " + pword_hash);

                } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                    noSuchAlgorithmException.printStackTrace();
                }

                enc_lusername = aes_enc.encrypt(lusername);
                enc_lpassword = aes_enc.encrypt(pword_hash);

                //System.out.println("USername : " + enc_lusername + "Password : " + enc_lpassword);
                //System.out.println("USername : " + aes_enc.decrypt(enc_lusername) + "Password : " + aes_enc.decrypt(enc_lpassword));

                try{
                    Class.forName("net.sourceforge.jtds.jdbc.Driver");
                    Connection con=DriverManager.getConnection("jdbc:jtds:sqlserver://"+ip_db+":1433/"+database_name,username_db,password_db);
                    Statement st=con.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_READ_ONLY);

                    ResultSet resultSet = st.executeQuery("SELECT * FROM [q7jxZAq0cKZ/kUZQyhiZNQ==] WHERE username = '" + enc_lusername + "' AND pwhash = '" + enc_lpassword + "'");

                    if(resultSet.next())
                    {
                        System.out.println("Existing user!");

                        select.setVisible(true);
                        selectname.setVisible(true);
                        li.setVisible(true);
                        li2.setVisible(true);
                        li3.setVisible(true);
                        li4.setVisible(true);
                        li5.setVisible(true);
                        la.setVisible(true);
                        la1.setVisible(true);
                        la2.setVisible(true);
                        la3.setVisible(true);
                        val1.setVisible(true);
                        val2.setVisible(true);
                        val3.setVisible(true);
                        attr1.setVisible(true);
                        attr2.setVisible(true);
                        attr3.setVisible(true);
                        nam.setVisible(true);
                        t1.setVisible(true);
                        convert.setVisible(true);
                        clear.setVisible(true);
                        pass_login.setVisible(false);
                        pass_login_field.setVisible(false);
                        username_login.setVisible(false);
                        username_login_field.setVisible(false);
                        button.setVisible(false);

                        heading_label.setText("Welcome " + lusername + "!");

                    }
                    else
                    {
                        System.out.println("No account!");
                    }

                    con.close();

                }catch(Exception ee)
                {
                    System.out.println("Error in connection" + ee);
                }

            }
        });

        clear.addActionListener(e -> {
            if(encrypted_table!=null)
                encrypted_table.dispose();
            if(decrypted_table!=null)
                decrypted_table.dispose();
            t1.setText("");

            attr1.setText("");
            attr2.setText("");
            attr3.setText("");
            nam.setText("");
            val1.setText("");
            val2.setText("");
            val3.setText("");

            selectname.setText("");
        });
        convert.addActionListener(e -> {

            String n1 = val1.getText();

            if(!serverip.getText().equals(""))
                ip_db=serverip.getText();
            if(!dbname.getText().equals(""))
                database_name=dbname.getText();
            if(!username.getText().equals(""))
                username_db=username.getText();
            if(!pass.getText().equals(""))
                password_db=pass.getText();

            if(!val1.getText().equals("")){
                String n2= val2.getText();
                String n3 = val3.getText();
                String n4=t1.getText();
                insert_into_table(n1,n2,n3,n4);}
            else if(!nam.getText().equals("")){
                String na1=nam.getText();
                String na2=attr1.getText();
                String na3=attr2.getText();
                String na4=attr3.getText();
                create_table(na1,na2,na3,na4);
            }
            else if(!selectname.getText().equals("")){
                String tname = selectname.getText();
                display_from_table(tname);
            }});

        select.setVisible(false);
        selectname.setVisible(false);
        li.setVisible(false);
        li2.setVisible(false);
        li3.setVisible(false);
        li4.setVisible(false);
        li5.setVisible(false);
        la.setVisible(false);
        la1.setVisible(false);
        la2.setVisible(false);
        la3.setVisible(false);
        val1.setVisible(false);
        val2.setVisible(false);
        val3.setVisible(false);
        attr1.setVisible(false);
        attr2.setVisible(false);
        attr3.setVisible(false);
        nam.setVisible(false);
        t1.setVisible(false);
        convert.setVisible(false);
        clear.setVisible(false);

        view_layout.add(dblabel);
        view_layout.add(dbname);
        main_view_frame.add(view_layout);
        view_layout = new JPanel();
        view_layout.setLayout(new FlowLayout());

        view_layout.add(userlabel);
        view_layout.add(username);
        main_view_frame.add(view_layout);
        view_layout = new JPanel();
        view_layout.setLayout(new FlowLayout());

        view_layout.add(passlabel);
        view_layout.add(pass);
        main_view_frame.add(view_layout);
        view_layout = new JPanel();
        view_layout.setLayout(new FlowLayout());

        view_layout.add(ip);
        view_layout.add(serverip);
        main_view_frame.add(view_layout);

        view_layout.add(username_login);
        view_layout.add(username_login_field);
        main_view_frame.add(view_layout);

        view_layout.add(pass_login);
        view_layout.add(pass_login_field);

        main_view_frame.add(view_layout);

        view_layout = new JPanel();

        view_layout.add(li);
        view_layout.add(nam);
        view_layout.add(li2);
        view_layout.add(attr1);
        view_layout.add(li3);
        view_layout.add(attr2);
        view_layout.add(li4);
        view_layout.add(attr3);
        view_layout.add(li5);
        main_view_frame.add(view_layout);
        view_layout = new JPanel();
        view_layout.setLayout(new FlowLayout());
        view_layout.add(la);
        view_layout.add(t1);
        view_layout.add(la1);
        view_layout.add(val1);
        view_layout.add(la2);
        view_layout.add(val2);
        view_layout.add(la3);
        view_layout.add(val3);
        main_view_frame.add(view_layout);
        view_layout = new JPanel();
        view_layout.setLayout(new FlowLayout());

        main_view_frame.add(view_layout);
        view_layout = new JPanel();
        view_layout.setLayout(new FlowLayout());

        main_view_frame.add(view_layout);
        view_layout = new JPanel();
        view_layout.setLayout(new FlowLayout());

        view_layout.add(select);
        view_layout.add(selectname);
        main_view_frame.add(view_layout);
        view_layout = new JPanel();
        view_layout.setLayout(new FlowLayout());

        view_layout.add(convert);
        view_layout.add(clear);
        view_layout.add(button);
        main_view_frame.add(view_layout);
        view_layout = new JPanel();
        view_layout.setLayout(new FlowLayout());

        main_view_frame.setVisible(true);

    }

    public static byte[] get_SHA256(String input) throws NoSuchAlgorithmException
    {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        return md.digest(input.getBytes(StandardCharsets.UTF_8));
    }

    public static String to_Hexa_String(byte[] hash)
    {
        BigInteger number = new BigInteger(1, hash);

        StringBuilder hexa_string = new StringBuilder(number.toString(16));

        while (hexa_string.length() < 32)
        {
            hexa_string.insert(0, '0');
        }

        return hexa_string.toString();
    }
}

