package client.proximity.bluetooth.tobias.zuber.mc.fhooe.at.btproximityclient.Bluetooth;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;
import android.util.Log;

import java.io.IOException;
import java.util.UUID;

public class AcceptThread extends Thread {

    private static final String TAG = "BT-AccT";

    private final UUID MY_UUID = UUID.fromString("4e5d48e0-75df-11e3-981f-0800200c9a66");
    private BluetoothServerSocket mBTServerSocket;

    public AcceptThread(BluetoothAdapter _adapter) {
        BluetoothServerSocket btServerSocket = null;

        try {
            btServerSocket = _adapter.listenUsingInsecureRfcommWithServiceRecord("btProximity", MY_UUID);
        } catch (IOException e) {
            Log.e(TAG, "AcceptThread: listen() failed");
        }
        mBTServerSocket = btServerSocket;
    }

    @Override
    public void run() {
        BluetoothSocket btSocket;
        BTManager btManager = BTManager.getInstance();

        // Listen to the server socket if we are not connected
        while (btManager.getState() != BTManager.STATE_CONNECTED) {
            try {
                btSocket = mBTServerSocket.accept(); // method call blocks
            } catch (IOException e) {
                Log.e(TAG, "accept() failed");
                break;
            }

            // IF a connection was accepted
            if (btSocket != null) {
                synchronized (btManager) {
                    switch (btManager.getState()) {
                        case BTManager.STATE_LISTEN:
                        case BTManager.STATE_CONNECTING:
                            // Situation normal. Start the connected Thread.
                            btManager.connected(btSocket);
                            break;
                        case BTManager.STATE_NONE:
                        case BTManager.STATE_CONNECTED:
                            // Either not ready or already connected. Terminate new socket
                            try {
                                btSocket.close();
                            } catch (IOException e) {
                                Log.e(TAG, "Cloud not close unwanted socket", e);
                            }
                            break;
                    }
                }
            }
        }
    }

    public void cancel() {
        try {
            mBTServerSocket.close();
        } catch (IOException e) {
            Log.e(TAG, "close() of Server Socket failed", e);
        }
    }
}
