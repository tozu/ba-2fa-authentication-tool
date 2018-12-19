package client.proximity.bluetooth.tobias.zuber.mc.fhooe.at.btproximityclient.Bluetooth;

import android.app.Service;
import android.bluetooth.BluetoothSocket;
import android.content.Context;
import android.util.Log;

import org.spongycastle.util.encoders.Base64;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;

import client.proximity.bluetooth.tobias.zuber.mc.fhooe.at.btproximityclient.utils.Encryption;
import client.proximity.bluetooth.tobias.zuber.mc.fhooe.at.btproximityclient.MyService;

public class ConnectedThread extends Thread {

    private static final String TAG = "BT-ConnT";

    private Context mContext;
    private static Service mService;

    private final BluetoothSocket mBTSocket;

    private final InputStream mInputStream;
    private final OutputStream mOutputStream;

    private Encryption encManager;
    private byte[] tempValue;
    private boolean expect_otp = false;
    private boolean awaits_proof = false;

    public ConnectedThread(BluetoothSocket _socket, Service _service) {
        mService = _service;
        mBTSocket = _socket;

        encManager = Encryption.getInstance(mService);

        InputStream input = null;
        OutputStream output = null;

        try {
            input = _socket.getInputStream();
            output = _socket.getOutputStream();
        } catch (IOException e) {
            Log.e(TAG, "socket streams not created", e);
        }

        mInputStream = input;
        mOutputStream = output;
    }

    @Override
    public void run() {
        Log.d(TAG, "BEGIN CONNECTEDthread");

        BTManager btManager = BTManager.getInstance();
        BufferedReader reader;
        OutputStreamWriter writer;

        // Keep listening to the inputStream while connected
        while (true /* btManager.getState() == BTManager.STATE_CONNECTED */) {
            try {
                // Read from the inputStream
                reader = new BufferedReader(new InputStreamReader(mInputStream));
                String receivedString = reader.readLine();

                Log.d(TAG, "received: " + receivedString);

                if (receivedString.length() != 0) {
                    writer = new OutputStreamWriter(mOutputStream);

                    byte[] decoded = Base64.decode(receivedString);
                    String payload = clientReply(decoded);
                    Log.d(TAG, "payload: " + payload);

                    // write send payload to client
                    writer.write(payload + "\r\n");
                    writer.flush();

                }
            } catch (IOException e) {
                Log.e(TAG, "DISCONNECTED!");
                // start over
                btManager.start();
                break;
            }
        }
    }

    public void cancel() {
        Log.d(TAG, "CANCEL CONNECTEDthread");
        try {
            mBTSocket.close();
        } catch (IOException e) {
            Log.e(TAG, "close() of connected socket failed", e);
        }
    }

    private synchronized String clientReply(byte[] decodedInput) {

        final byte[] DAEMON_REQUEST_PUBLIC_KEY = "0-".getBytes();
        final byte[] DAEMON_REQUESTS_OTP = "1-".getBytes();
        final byte[] DAEMON_SENDS_OTP = "2-".getBytes();
        final byte[] DAEMON_REQUESTS_HMAC_OTP = "3-".getBytes();
        final byte[] BTCLIENT_CONFIRMATION = "4-".getBytes();
        final byte[] DAEMON_REQUESTS_KEY = "6-".getBytes();
        final byte[] BTCLIENT_REFUSES = "-7".getBytes();
        final byte[] BTCLIENT_AWAITS_PROOF = "10-".getBytes();

        String reply = null;
        boolean requestedPB = false;

        // capture known input
        if (encManager.verifyRSA(DAEMON_REQUEST_PUBLIC_KEY, decodedInput, encManager.getPublicKeyDaemon())) {
            Log.d(TAG, "[Public Key REQUEST]");
            requestedPB = true;
            decodedInput = encManager.getPublicKey().getEncoded();

        } else if (encManager.verifyRSA(DAEMON_REQUESTS_OTP, decodedInput, encManager.getPublicKeyDaemon())) {
            Log.d(TAG, "[OTP REQUEST]");
            reply = encManager.getOTP();
            
        } else if (encManager.verifyRSA(DAEMON_REQUESTS_HMAC_OTP, decodedInput, encManager.getPublicKeyDaemon())) {
            Log.d(TAG, "[HMAC REQUEST]");
            String otp = encManager.getOTP();
            String key = encManager.getHMACKey();
            reply = encManager.createHMAC(otp, key);

        } else if (encManager.verifyRSA(DAEMON_SENDS_OTP, decodedInput, encManager.getPublicKeyDaemon())) {
            Log.d(TAG, "[BT Client expects OTP]");
            expect_otp = true;
            reply = new String(BTCLIENT_CONFIRMATION);
        } else {                                    // capture unknown input
            Log.d(TAG, "[received sth else...]");
            if (expect_otp) {
                tempValue = decodedInput;
                expect_otp = false;
                awaits_proof = true;
                reply = new String(BTCLIENT_AWAITS_PROOF);
            } else if (awaits_proof) {
                Log.d(TAG, "\tgoing to verify...");
                if (encManager.verifyRSA(tempValue, decodedInput, encManager.getPublicKeyDaemon())) {
                    String otp = encManager.decryptRSA(tempValue, encManager.getPrivateKey());
                    tempValue = null;
                    if (encManager.updateOTP(otp)) {
                        Log.d(TAG, "\t...verified Daemon AND could SAVE new OTP!");
                        reply = new String(BTCLIENT_CONFIRMATION);
                    } else {
                        Log.d(TAG, "\t...verified Daemon BUT could NOT SAVE new OTP!");
                        reply = new String(BTCLIENT_REFUSES);
                    }
                } else {
                    Log.d(TAG, "\t...could NOT verify Daemon!");
                    reply = new String(BTCLIENT_REFUSES);
                }
                awaits_proof = false;
            } else {
                Log.e(TAG, "[ERROR!]");
                awaits_proof = false;
                tempValue = null;
                reply = new String(BTCLIENT_REFUSES);
            }
        }

        if (!requestedPB) {
            decodedInput = encManager.encryptRSA(reply, encManager.getPublicKeyDaemon());  // encrypted (with PB-D) and encoded
        }

        return Base64.toBase64String(decodedInput);                                       // encode payload
    }
}
