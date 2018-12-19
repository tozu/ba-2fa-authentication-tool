package client.proximity.bluetooth.tobias.zuber.mc.fhooe.at.btproximityclient;

import android.app.Service;
import android.bluetooth.BluetoothAdapter;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.IBinder;
import android.util.Log;
import android.widget.Toast;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import client.proximity.bluetooth.tobias.zuber.mc.fhooe.at.btproximityclient.Bluetooth.BTManager;
import client.proximity.bluetooth.tobias.zuber.mc.fhooe.at.btproximityclient.utils.Encryption;

public class MyService extends Service {

    private static final String TAG = "BT-Service";
    private BluetoothAdapter mBluetoothAdapter;

    private SharedPreferences sharedpreferences;

    private Encryption encManager;

    public MyService() {
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onCreate() {
        super.onCreate();

        mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        sharedpreferences = getApplicationContext().getSharedPreferences("btProximity", Context.MODE_PRIVATE);

        encManager = Encryption.getInstance(getApplicationContext());
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "BT Service runs!");

        startBluetoothManager();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Toast.makeText(this, "Service Stopped", Toast.LENGTH_SHORT).show();
    }

    void startBluetoothManager() {
        BTManager btManager = BTManager.newInstance(this, mBluetoothAdapter);
        btManager.start();
        Toast.makeText(getApplicationContext(), "listening for devices", Toast.LENGTH_SHORT).show();
    }

}
