package lu.uni.trux.difuzer.ocsvm;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import libsvm.svm;
import libsvm.svm_model;
import libsvm.svm_node;
import lu.uni.trux.difuzer.FeatureVector;
import lu.uni.trux.difuzer.utils.Constants;

public class PredictOCSVM {

	private static PredictOCSVM instance;

	private svm_model model;
	private int svm_type;
	private int nr_class;

	private PredictOCSVM() {
		this.loadDefaultModel();
	}

	public static PredictOCSVM v() {
		if(instance == null) {
			instance = new PredictOCSVM();
		}
		return instance;
	}

	private void loadDefaultModel() {
		if(model == null) {
			this.loadModel(Constants.TRIGGER_MODEL_FILE);
		}
	}

	public double predict(FeatureVector fv) {
		if(this.model == null) {
			System.err.println("No model available.");
			return 0;
		}else {
			svm_node[] node = null;
			int vectorSize;
			double prediction;
			vectorSize = fv.getSize();
			String[] values = fv.toStringArray();
			node = new svm_node[vectorSize];
			for(int i = 0 ; i < vectorSize ; i++) {
				node[i] = new svm_node();
				node[i].index = i;
				node[i].value = Double.parseDouble(values[i]);
			}
			prediction = svm.svm_predict(model, node);
			return prediction;
		}
	}

	public void loadModel(String path) {
		try {
			InputStream fis =  this.getClass().getResourceAsStream(path);
			BufferedReader br = new BufferedReader(new InputStreamReader(fis));
			this.model = svm.svm_load_model(br);
			if(model != null) {
				this.svm_type = svm.svm_get_svm_type(this.model);
				this.nr_class = svm.svm_get_nr_class(this.model);
			}
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
	}

	public int getSvm_type() {
		return svm_type;
	}

	public void setSvm_type(int svm_type) {
		this.svm_type = svm_type;
	}

	public int getNr_class() {
		return nr_class;
	}

	public void setNr_class(int nr_class) {
		this.nr_class = nr_class;
	}
}
