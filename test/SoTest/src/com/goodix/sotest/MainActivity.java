package com.goodix.sotest;

import com.goodix.sotest.R;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

public class MainActivity extends Activity {

    static {
        System.loadLibrary("mathc");
        System.loadLibrary("unload");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        init();
    }

    private void init() {
        final Button mathAddButton = (Button) findViewById(R.id.math_add);
        final TextView resultView = (TextView) findViewById(R.id.result_text_view);
        mathAddButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                int sum = NativeMath.add(2, 3);
                resultView.setText(String.valueOf(sum));
            }
        });
        final Button soUnloadButton = (Button) findViewById(R.id.so_unload);
        soUnloadButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View arg0) {
                NativeMath.unload();
            }
        });
    }
}
