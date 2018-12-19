package client.proximity.bluetooth.tobias.zuber.mc.fhooe.at.btproximityclient.Bluetooth;

import android.app.Activity;
import android.app.Service;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothSocket;
import android.content.Context;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

public class BTManager {

    private static final String TAG = "BT-Manager";
    private static Service mService;

    private BluetoothAdapter mBTAdapter;

    private int mState;
    public static final int STATE_NONE = 0;
    public static final int STATE_LISTEN = 1;
    public static final int STATE_CONNECTING = 2;
    public static final int STATE_CONNECTED = 3;
    public static final int STATE_SEND = 4;

    private AcceptThread mAcceptThread;
    private ConnectedThread mConnectedThread;

    private static BTManager mInstance;

    public static BTManager getInstance() {
        return mInstance;
    }

    public static BTManager newInstance(Service _service, BluetoothAdapter _adapter) {
        if(mInstance == null) {
            mInstance = new BTManager(_service, _adapter);
        }
        return getInstance();
    }

    private BTManager(Service _service, BluetoothAdapter _adapter) {
        mService = _service;
        mBTAdapter = _adapter;
        mState = STATE_NONE;
    }

    public synchronized void setState(int state) {
        Log.d(TAG, "setState: " + mState + " -> " + state);
        mState = state;
    }

    public synchronized int getState() {
        return mState;
    }

    public synchronized void start() {
        Log.d(TAG, "[start]");

        // cancel any thread currently running a connection
        if (mConnectedThread != null) {
            mConnectedThread.cancel();
            mConnectedThread = null;
        }

        setState(STATE_LISTEN);

        // start the thread to listen on a BluetoothServerSocket
        if (mAcceptThread == null) {
            mAcceptThread = new AcceptThread(mBTAdapter);
            mAcceptThread.start();
        }
    }

    public synchronized void stop() {
        Log.d(TAG, "[stop]");

        if (mConnectedThread != null) {
            mConnectedThread.cancel();
            mConnectedThread = null;
        }

        if (mAcceptThread != null) {
            mAcceptThread.cancel();
            mAcceptThread = null;
        }
        setState(STATE_NONE);
    }

    public synchronized void connected(BluetoothSocket _socket) {
        Log.d(TAG, "[connected]");

        // cancel the thread currently running a connection
        if(mConnectedThread != null) {
            mConnectedThread.cancel();
            mConnectedThread = null;
        }

        if(mAcceptThread != null) {
            mAcceptThread.cancel();
            mAcceptThread = null;
        }

        // Start the thread to manage the connection and perform transmissions
        mConnectedThread = new ConnectedThread(_socket, mService);
        mConnectedThread.start();

        setState(STATE_CONNECTED);
    }
}
