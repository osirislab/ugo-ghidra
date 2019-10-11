package ugo.lang;

public enum UgoDecompilerLanguage {
    GO_LANGUAGE("go-language");

    private final String optionString;
    UgoDecompilerLanguage(String optionString) { this.optionString = optionString; }

    @Override
    public String toString() { return optionString; }
}


