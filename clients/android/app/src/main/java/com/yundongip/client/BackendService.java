package com.yundongip.client;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

import java.io.File;

public class BackendService extends Service {
    private static final String CHANNEL_ID = "yundongip_runtime";
    private Process backend;
    private PowerManager.WakeLock wakeLock;

    @Override public void onCreate() {
        super.onCreate();
        createChannel();

        Intent open = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(
            this, 0, open,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        Notification n = new Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("YunDongIP 正在运行")
            .setContentText("本机自动优选服务已启动")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true)
            .setContentIntent(pi)
            .build();

        startForeground(13335, n);

        PowerManager pm = (PowerManager)getSystemService(POWER_SERVICE);
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "YunDongIP:Backend");
        wakeLock.setReferenceCounted(false);
        wakeLock.acquire();

        startBackend();
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "YunDongIP 后台服务", NotificationManager.IMPORTANCE_LOW
            );
            ch.setDescription("保持 YunDongIP 自动优选服务在手机本机运行");
            NotificationManager nm = getSystemService(NotificationManager.class);
            nm.createNotificationChannel(ch);
        }
    }

    private synchronized void startBackend() {
        if (backend != null && backend.isAlive()) return;
        try {
            String nativeDir = getApplicationInfo().nativeLibraryDir;
            File exe = new File(nativeDir, "libyundongip.so");
            ProcessBuilder pb = new ProcessBuilder(
                exe.getAbsolutePath(),
                "-host", "127.0.0.1",
                "-port", "13335",
                "-open-browser=false"
            );
            pb.directory(getFilesDir());
            pb.redirectErrorStream(true);
            backend = pb.start();
        } catch (Exception ignored) {
        }
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        startBackend();
        return START_STICKY;
    }

    @Override public void onTaskRemoved(Intent rootIntent) {
        startBackend();
        super.onTaskRemoved(rootIntent);
    }

    @Override public void onDestroy() {
        if (backend != null) backend.destroy();
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        super.onDestroy();
    }

    @Override public IBinder onBind(Intent intent) {
        return null;
    }
}
