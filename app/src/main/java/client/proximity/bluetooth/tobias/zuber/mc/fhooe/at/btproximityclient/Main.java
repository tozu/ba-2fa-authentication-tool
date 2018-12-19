package client.proximity.bluetooth.tobias.zuber.mc.fhooe.at.btproximityclient;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.AlertDialog;
import android.bluetooth.BluetoothAdapter;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;

import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.View;
import android.widget.CompoundButton;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.Switch;
import android.widget.Toast;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import client.proximity.bluetooth.tobias.zuber.mc.fhooe.at.btproximityclient.utils.Encryption;

public class Main extends AppCompatActivity {

    private static final String TAG = "BT-Main";

    private BluetoothAdapter mBluetoothAdapter;

    private SharedPreferences sharedpreferences;
    public static final int READ_REQUEST_CODE = 12;
    private Encryption encManager;

    private Switch swService, swBT;
    private ImageView ivBT, ivDPB, ivHMAC;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        if (mBluetoothAdapter == null) {
            Toast.makeText(getApplicationContext(), "Bluetooth is mandatory!", Toast.LENGTH_SHORT).show();
            finish();
        }

        sharedpreferences = getSharedPreferences("btProximity", Context.MODE_PRIVATE);
        encManager = Encryption.getInstance(this);

        setContentView(R.layout.activity_main);

        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        getSupportActionBar().setTitle(R.string.app_name);

        initViews();
        updateViews();
    }

    // Views
    private void initViews() {
        RelativeLayout lDaemonKey = (RelativeLayout) findViewById(R.id.layoutDPB);
        lDaemonKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                encManager.loadPublicKeyDaemonFromFile();
            }
        });

        RelativeLayout lHMAC = (RelativeLayout) findViewById(R.id.layoutHMAC);
        lHMAC.setOnClickListener(new View.OnClickListener() {
           @Override
           public void onClick(View v) {
              AlertDialog.Builder builder = new AlertDialog.Builder(this);
              builder.setTitle("Please enter HMAC");

              // Set up the input
              final EditText input = new EditText(this);
              input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
              builder.setView(input);

              // Set up the buttons
              builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
                  @Override
                  public void onClick(DialogInterface dialog, int which) {
                      if(input.getText().toString() != null) {
                        encManager.updateHMACKey(input.getText().toString());
                        updateViews();
                      }
                  }
              });
              builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                  @Override
                  public void onClick(DialogInterface dialog, int which) {
                      dialog.cancel();
                  }
              });
              builder.show();
           }
         });

        swService = (Switch) findViewById(R.id.switchService);
        swService.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    startService();
                } else {
                    stopService();
                }
                updateViewService();
            }
        });
        swBT = (Switch) findViewById(R.id.swBT);
        swBT.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    enableBluetooth();
                } else {
                    // disable Bluetooth
                }
                updateViewBT();
            }
        });

        ivBT = (ImageView) findViewById(R.id.ivBT);
        ivDPB = (ImageView) findViewById(R.id.ivDPB);
        ivHMAC = (ImageView) findViewById(R.id.ivHMAC);
    }

    private void updateViews() {
        updateViewBT(); // check if bluetooth is on
        updateViewDaemonPublicKey(); // check if Daemons Public Key could be fetched

        updateViewHMAC(); // check if keys are set
        updateViewService(); // check if Service is running
    }

    private boolean updateViewBT() {
        if (mBluetoothAdapter.isEnabled()) {
            swBT.setChecked(true);
            ivBT.setImageResource(R.drawable.ic_done_black_24dp);
            return true;
        } else {
            swBT.setChecked(false);
            ivBT.setImageResource(R.drawable.ic_error_black_24dp);
            return false;
        }
    }

    private boolean updateViewDaemonPublicKey() {
        String pathToPBDaemon = sharedpreferences.getString("pathPBDaemon", null);
        Log.d(TAG, "fetchPublicKeyDaemon: path to pb-key: " + pathToPBDaemon);

        if (pathToPBDaemon != null) {
            ivDPB.setImageResource(R.drawable.ic_done_black_24dp);
            return true;
        } else {
            ivDPB.setImageResource(R.drawable.ic_error_black_24dp);
            return false;
        }
    }

    private boolean updateViewHMAC() {
        String hmac = sharedpreferences.getString("hmac", null);

        if (hmac != null) {
            ivHMAC.setImageResource(R.drawable.ic_done_black_24dp);
            return true;
        } else {
            ivHMAC.setImageResource(R.drawable.ic_error_black_24dp);
            return false;
        }
    }

    private void updateViewService() {
        if (isServiceRunning(MyService.class)) {
            swService.setChecked(true);
        } else {
            swService.setChecked(false);
        }
    }

    // Service
    private void startService() {
        if (!isServiceRunning(MyService.class)) {
            Intent startService = new Intent(this, MyService.class);
            startService(startService);
        }
    }

    private void stopService() {
        Intent stopService = new Intent(this, MyService.class);
        stopService(stopService);
    }

    private boolean isServiceRunning(Class<?> _serviceClass) {
        ActivityManager actManager = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
        for (ActivityManager.RunningServiceInfo service : actManager.getRunningServices(Integer.MAX_VALUE)) {
            if (_serviceClass.getName().equals(service.service.getClassName())) {
                return true;
            }
        }

        return false;
    }

    // Bluetooth
    private void enableBluetooth() {
        Intent enableIntent = null;
        if (!mBluetoothAdapter.isEnabled()) {
            enableIntent = new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE);
            enableIntent.putExtra(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE, 1);
            enableIntent.putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, 0);
            startActivityForResult(enableIntent, 1);
        }
        if (mBluetoothAdapter.getScanMode() != BluetoothAdapter.SCAN_MODE_CONNECTABLE_DISCOVERABLE) {
            if (enableIntent == null) {
                enableIntent = new Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE);
            }
            enableIntent.putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, 0);
            startActivityForResult(enableIntent, 1);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == READ_REQUEST_CODE && resultCode == Activity.RESULT_OK) {
            Uri uri;
            if (data != null) {
                uri = data.getData();

                try {
                    File file = new File(getFilesDir(), "daemon.pub");

                    InputStream is = getContentResolver().openInputStream(uri);
                    OutputStream out = new FileOutputStream(file);

                    byte[] buffer = new byte[1024];
                    int len;
                    while ((len = is.read(buffer)) != -1) {
                        out.write(buffer, 0, len);
                    }
                    out.close();
                    is.close();

                    // if successful is the public key loaded
                    if (encManager.loadPublicKeyDaemon(file.getPath())) {
                        // save path to sharedPref for next call
                        SharedPreferences.Editor editor = sharedpreferences.edit();
                        editor.putString("pathPBDaemon", file.getPath());
                        editor.commit();

                        encManager.loadDaemonsKeySuccessful = true;
                        updateViewDaemonPublicKey();
                    } else {
                        encManager.loadDaemonsKeySuccessful = false;
                    }
                } catch (FileNotFoundException e) {
                    Log.e(TAG, "onActivityResult: File not found ", e);
                } catch (IOException e) {
                    Log.e(TAG, "onActivityResult: IOE", e);
                }
            }
        }
    }
}
