#rallaf2022

"""Homework 2 RAG application.

This is the main application for the first RAG step. It reuses the course
architecture from the 02_LangChain/07_RAG examples instead of rewriting it:

- 07_rag_loaddb.py: load files, split them into chunks, embed, store in Chroma
- 08_rag_docsearch.py: retrieve similar chunks from the same vector database
- 09_rag_query.py: send retrieved context plus the user question to the LLM

Required environment variables:
    GOOGLE_API_KEY          API key used by ChatGoogleGenerativeAI
    GOOGLE_MODEL            Chat model name, for example gemini-2.0-flash
    GOOGLE_CLOUD_PROJECT    GCP project ID used by Vertex AI embeddings
"""

import os

# readline is used by the course examples for nicer terminal input history.
# It is not available on a default Windows Python install, so ignore it there.
try:
    import readline
except ImportError:
    pass

from langchain_chroma import Chroma
from langchain_community.document_loaders import (
    CSVLoader,
    DirectoryLoader,
    Docx2txtLoader,
    PyPDFDirectoryLoader,
    TextLoader,
    UnstructuredMarkdownLoader,
)
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_google_vertexai import VertexAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter


# Same persistent Chroma path used by 07_rag_loaddb.py, 08_rag_docsearch.py,
# 09_rag_query.py, and 10_chainlit_rag_query.py.
PERSIST_DIRECTORY = "./rag_data/.chromadb"

# Local document folders copied from the course rag_data directory.
TXT_DIRECTORY = "rag_data/txt"
PDF_DIRECTORY = "rag_data/pdf"
DOCX_DIRECTORY = "rag_data/docx"
MD_DIRECTORY = "rag_data/md"
CSV_DIRECTORY = "rag_data/csv"

# Same chunk settings as 07_rag_loaddb.py.
CHUNK_SIZE = 10000
CHUNK_OVERLAP = 10


def create_embedding_function():
    """Create the Vertex AI embedding model used by the course RAG examples.

    Vertex AI is used instead of Google AI Studio embeddings because the
    course notes that Studio embeddings hit quota limits when many chunks
    are sent at once.
    """
    return VertexAIEmbeddings(
        model_name="gemini-embedding-001",
        project=os.getenv("GOOGLE_CLOUD_PROJECT"),
        location="us-west1",
    )


def create_vectorstore():
    """Open or create the persistent Chroma vector database.

    Using persist_directory means embeddings are stored on disk and can be
    reused on later runs without reloading every document.
    """
    return Chroma(
        embedding_function=create_embedding_function(),
        persist_directory=PERSIST_DIRECTORY,
    )


def create_llm():
    """Create the chat model that answers questions from retrieved context."""
    return ChatGoogleGenerativeAI(
        model=os.getenv("GOOGLE_MODEL"),
        google_api_key=os.getenv("GOOGLE_API_KEY"),
    )


def create_prompt():
    """Return the local RAG prompt used in 09_rag_query.py."""
    return ChatPromptTemplate.from_template(
        """You are an assistant for question-answering tasks.
Use the following pieces of retrieved context to answer the question.
If you don't know the answer, just say that you don't know.
Use three sentences maximum and keep the answer concise.

Question: {question}

Context: {context}

Answer:"""
    )


# Shared objects used by loading and querying. Created once at import time,
# matching the script style of the course examples.
vectorstore = create_vectorstore()
retriever = vectorstore.as_retriever()
llm = create_llm()
prompt = create_prompt()


def load_docs(docs):
    """Split documents into chunks and store their embeddings in Chroma.

    This is the same helper used in 07_rag_loaddb.py.
    """
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
    )
    splits = text_splitter.split_documents(docs)
    vectorstore.add_documents(documents=splits)
    return splits


def load_txt(directory):
    """Load text files from a directory into the vector database."""
    load_docs(DirectoryLoader(directory, glob="**/*.txt", loader_cls=TextLoader).load())


def load_pdf(directory):
    """Load PDF files from a directory into the vector database."""
    load_docs(PyPDFDirectoryLoader(directory).load())


def load_docx(directory):
    """Load DOCX files from a directory into the vector database."""
    load_docs(DirectoryLoader(directory, glob="**/*.docx", loader_cls=Docx2txtLoader).load())


def load_md(directory):
    """Load Markdown files from a directory into the vector database."""
    load_docs(DirectoryLoader(directory, glob="**/*.md", loader_cls=UnstructuredMarkdownLoader).load())


def load_csv(directory):
    """Load CSV files from a directory into the vector database."""
    load_docs(DirectoryLoader(directory, glob="**/*.csv", loader_cls=CSVLoader).load())


def has_files(directory, extension):
    """Return True when a directory exists and contains the given file type."""
    if not os.path.isdir(directory):
        return False
    for root, _dirs, files in os.walk(directory):
        for name in files:
            if name.lower().endswith(extension):
                return True
    return False


def load_rag_data():
    """Load local rag_data files into Chroma using the course loaders.

    Only folders that actually contain matching files are loaded so empty
    directories do not cause errors.
    """
    if has_files(TXT_DIRECTORY, ".txt"):
        print(f"Loading TXT files from: {TXT_DIRECTORY}")
        load_txt(TXT_DIRECTORY)
    if has_files(PDF_DIRECTORY, ".pdf"):
        print(f"Loading PDF files from: {PDF_DIRECTORY}")
        load_pdf(PDF_DIRECTORY)
    if has_files(DOCX_DIRECTORY, ".docx"):
        print(f"Loading DOCX files from: {DOCX_DIRECTORY}")
        load_docx(DOCX_DIRECTORY)
    if has_files(MD_DIRECTORY, ".md"):
        print(f"Loading MD files from: {MD_DIRECTORY}")
        load_md(MD_DIRECTORY)
    if has_files(CSV_DIRECTORY, ".csv"):
        print(f"Loading CSV files from: {CSV_DIRECTORY}")
        load_csv(CSV_DIRECTORY)


def is_vectorstore_empty():
    """Return True if the Chroma database has no stored documents yet."""
    stored = vectorstore.get()
    return not stored.get("ids")


def format_docs(docs):
    """Join retrieved document contents into one prompt context string."""
    return "\n\n".join(doc.page_content for doc in docs)


# Same LCEL RAG chain as 09_rag_query.py:
# retrieve similar chunks, fill the prompt, call the model, return text.
rag_chain = (
    {"context": retriever | format_docs, "question": RunnablePassthrough()}
    | prompt
    | llm
    | StrOutputParser()
)


def print_sources():
    """Print the unique document sources stored in the vector database."""
    document_data_sources = set()
    for doc_metadata in retriever.vectorstore.get()["metadatas"]:
        if doc_metadata and "source" in doc_metadata:
            document_data_sources.add(doc_metadata["source"])
    for doc in document_data_sources:
        print(f"  {doc}")


def require_environment_variables():
    """Exit with a clear message if required API settings are missing."""
    required_names = ["GOOGLE_API_KEY", "GOOGLE_MODEL", "GOOGLE_CLOUD_PROJECT"]
    missing_names = [name for name in required_names if not os.getenv(name)]
    if missing_names:
        joined_names = ", ".join(missing_names)
        raise SystemExit(
            "Missing required environment variable(s): "
            f"{joined_names}. Set them before running app.py."
        )


def main():
    """Load rag_data if needed, then answer questions from retrieved documents."""
    require_environment_variables()
    print("RAG prompt:", prompt)
    if is_vectorstore_empty():
        print("Vector database is empty. Loading documents from rag_data.")
        load_rag_data()
    else:
        print("Vector database already has documents. Skipping reload.")
    print(
        "Welcome to my RAG application.  Ask me a question and I will "
        "answer it from the documents in my database shown below"
    )
    print_sources()
    while True:
        line = input("llm>> ")
        if line:
            result = rag_chain.invoke(line)
            print(result)
        else:
            break


if __name__ == "__main__":
    main()
