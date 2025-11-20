from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from agent.utils.model_factory import get_llm

### Document Grader chain
# For a given document, assesses whether it is relevant to the user's query
# TODO: might have to chage this to receive at least some of the messages

# Data model
class GradeDocuments(BaseModel):
    """Binary score for relevance check on retrieved documents."""

    binary_score: str = Field(
        description="Documents are relevant to the question, 'yes' or 'no'"
    )
        
llm = get_llm(size='small', temperature=0.1)

llm_grader = llm.with_structured_output(GradeDocuments)

grader_system_prompt = """You are a grader assessing the relevance of a retrieved API endpoint or glossary entry to a user question. \n
    if the document contains keywords(s) or semantic meaning relevant to the user's query or if it is an endpoint that would help them acheive a specified task, grade it as relevant.\n
    You may need to infer synonyms or related concepts to determine relevance. I.e. if a user asks about 'transactions', 'payments' may also be relevant.\n
    Or if a user asks about 'API information' 'API Metrics' may be relevant.\n 
    Give a binary score 'yes' or 'no', to indicate whether the document is relevant to the question.\n
    Only grade no if there is absolutely no relevance to the user's question.
"""

grader_prompt_template = ChatPromptTemplate.from_messages(
    [
        ("system", grader_system_prompt),
        ("human", "Retrieved document: \n\n {document} \n\n User question: {question}")
    ]
)

retrieval_grader = grader_prompt_template | llm_grader


### Question Re-writer
# NOTE: we may not end up using this in subsequent versions. Have to run retrieval graph against evals (also have to make evals)
# LLM
llm = get_llm(size='small', temperature=0.7)

# Prompt
system = """You are a question re-writer that converts an input question to a better version that is designed to find endpoints\n 
     in a vector index of API endpoints. Look at the input and try to reason about the underlying semantic intent / meaning.\n
     Reword the question in such a way so that vector search could find endpoints that would help the user acheive their task.
     Try different keywords/synonyms and API jargon if needed.
     
     Here are a list of API endpoint tags that you can use to help you re-write the question. Each tag is a keyword that is associated with a group of endpoints.
     Use the most relevant tags in the re-written question to help the vector search find the most relevant endpoints.
        
        - Old-Style
        - Transaction-Request
        - API
        - Bank
        - Account
        - Account-Access
        - Direct-Debit
        - Standing-Order
        - Account-Metadata
        - Account-Application
        - Account-Public
        - Account-Firehose
        - FirehoseData
        - PublicData
        - PrivateData
        - Transaction
        - Transaction-Firehose
        - Counterparty-Metadata
        - Transaction-Metadata
        - View-Custom
        - View-System
        - Entitlement
        - Role
        - Scope
        - OwnerViewRequired
        - Counterparty
        - KYC
        - Customer
        - Onboarding
        - User
        - User-Invitation
        - Customer-Meeting
        - Experimental
        - Person
        - Card
        - Sandbox
        - Branch
        - ATM
        - Product
        - Product-Collection
        - Open-Data
        - Consumer
        - Data-Warehouse
        - FX
        - Customer-Message
        - Metric
        - Documentation
        - Berlin-Group
        - Signing Baskets
        - UKOpenBanking
        - MXOpenFinance
        - Aggregate-Metrics
        - System-Integrity
        - Webhook
        - Mocked-Data
        - Consent
        - Method-Routing
        - WebUi-Props
        - Endpoint-Mapping
        - Rate-Limits
        - Counterparty-Limits
        - Api-Collection
        - Dynamic-Resource-Doc
        - Dynamic-Message-Doc
        - DAuth
        - Dynamic
        - Dynamic-Entity
        - Dynamic-Entity-Manage
        - Dynamic-Endpoint
        - Dynamic-Endpoint-Manage
        - JSON-Schema-Validation
        - Authentication-Type-Validation
        - Connector-Method
        - Berlin-Group-M
        - PSD2
        - Account Information Service (AIS)
        - Confirmation of Funds Service (PIIS)
        - Payment Initiation Service (PIS)
        - Directory
        - UK-AccountAccess
        - UK-Accounts
        - UK-Balances
        - UK-Beneficiaries
        - UK-DirectDebits
        - UK-DomesticPayments
        - UK-DomesticScheduledPayments
        - UK-DomesticStandingOrders
        - UK-FilePayments
        - UK-FundsConfirmations
        - UK-InternationalPayments
        - UK-InternationalScheduledPayments
        - UK-InternationalStandingOrders
        - UK-Offers
        - UK-Partys
        - UK-Products
        - UK-ScheduledPayments
        - UK-StandingOrders
        - UK-Statements
        - UK-Transactions
        - AU-Banking
     """
re_write_prompt = ChatPromptTemplate.from_messages(
    [
        ("system", system),
        (
            "human",
            "Here is the initial question: \n\n {question} \n Formulate an improved question.",
        ),
    ]
)

endpoint_question_rewriter = re_write_prompt | llm | StrOutputParser()


