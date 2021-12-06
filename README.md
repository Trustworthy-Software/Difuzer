# Difuzer

In this repository, we host Difuzer, a static logic bomb detector. Difuzer relies on static inter-procedural taint analysis to find sensitive trigger entry-points in Android apps.
It is able to filter abnormal triggers known as Hidden Sensitive Operations from trigger-specific features.

## Getting started

### Downloading the tool

<pre>
git clone https://github.com/JordanSamhi/Difuzer.git
</pre>

### Installing the tool

<pre>
cd Difuzer
mvn clean install
</pre>

<pre>
java -jar Difuzer/target/Difuzer-0.1-jar-with-dependencies.jar <i>options</i>
</pre>

Options:

* ```-a``` : The path to the APK to process.
* ```-p``` : The path to Android platofrms folder.
* ```-r``` : Displays raw results.
* ```-t``` : Set the timeout of the analysis.
* ```-e``` : Set an EasyTaintWrapper file.

## Built With

* [Maven](https://maven.apache.org/) - Dependency Management

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details

## Contact

For any question regarding this study, please contact us at:
[Jordan Samhi](mailto:jordan.samhi@uni.lu)
